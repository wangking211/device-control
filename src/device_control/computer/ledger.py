"""Durable, cross-process-safe local ledger for Computer Runtime actions.

The ledger remembers only scoped identifiers and status. It never stores tokens,
approval nonces, lease credentials or raw UI/browser payloads.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

LEDGER_SCHEMA = "dc.computer-ledger/v2"
LEGACY_LEDGER_SCHEMA = "dc.computer-ledger/v1"
MAX_ENTRIES = 500
UNRESOLVED_PHASES = frozenset({"executing", "unknown", "uncertain", "recovering"})


class LedgerCorrupt(RuntimeError):
    pass


class LedgerCapacity(RuntimeError):
    pass


@dataclass
class LedgerEntry:
    schema: str
    tenant_ref: str
    endpoint_id: str
    idempotency_key: str
    fingerprint: str
    phase: str  # executing | unknown | uncertain | recovering | completed
    command_id: str
    task_ref: str = ""
    run_ref: str = ""
    result: dict[str, Any] | None = None
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ComputerRunLedger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path(
            os.environ.get("COMPUTER_RUNTIME_LEDGER") or "./var/computer-ledger.json"
        )
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._entries: dict[str, LedgerEntry] = {}
        self._load()

    @staticmethod
    def key(tenant_ref: str, endpoint_id: str, task_ref: str,
            run_ref: str, idempotency_key: str) -> str:
        return "|".join((tenant_ref, endpoint_id, task_ref, run_ref, idempotency_key))

    @staticmethod
    def _entry_key(entry: LedgerEntry) -> str:
        return ComputerRunLedger.key(entry.tenant_ref, entry.endpoint_id,
                                     entry.task_ref, entry.run_ref,
                                     entry.idempotency_key)

    def get(self, key: str) -> LedgerEntry | None:
        return self._entries.get(key)

    def unresolved(self) -> list[LedgerEntry]:
        return [entry for entry in self._entries.values()
                if entry.phase in UNRESOLVED_PHASES]

    def record(self, entry: LedgerEntry) -> None:
        with self._file_lock():
            # Re-read under the lock so two processes cannot lose updates.
            self._entries = self._read_entries()
            previous = self._entries.get(self._entry_key(entry))
            if previous and previous.fingerprint != entry.fingerprint:
                raise RuntimeError("computer_ledger_fingerprint_conflict")
            if (len(self._entries) >= MAX_ENTRIES
                    and self._entry_key(entry) not in self._entries):
                # Never evict unresolved safety records. Fail closed instead.
                raise LedgerCapacity("computer_ledger_capacity_reached")
            self._entries[self._entry_key(entry)] = entry
            self._persist()

    def mark_unknown(self, key: str, *, reason: str = "unknown") -> LedgerEntry | None:
        with self._file_lock():
            self._entries = self._read_entries()
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry.phase = "unknown"
            entry.result = {"status": "uncertain", "error_code": reason}
            entry.updated_at = datetime.now(timezone.utc).isoformat()
            self._entries[key] = entry
            self._persist()
            return entry

    def _load(self) -> None:
        self._entries = self._read_entries()

    def _read_entries(self) -> dict[str, LedgerEntry]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LedgerCorrupt("computer_ledger_corrupt") from exc
        if not isinstance(data, dict) or data.get("schema") not in {
            LEDGER_SCHEMA, LEGACY_LEDGER_SCHEMA,
        }:
            raise LedgerCorrupt("computer_ledger_corrupt")
        entries: dict[str, LedgerEntry] = {}
        for item in data.get("entries") or []:
            try:
                item = dict(item)
                if data.get("schema") == LEGACY_LEDGER_SCHEMA:
                    # Legacy v1 omitted task/run and may not be replayable.
                    item.setdefault("task_ref", "")
                    item.setdefault("run_ref", "")
                    if item.get("phase") not in {"unknown", "uncertain", "executing"}:
                        item["phase"] = "unknown"
                entry = LedgerEntry(**item)
            except (TypeError, ValueError) as exc:
                raise LedgerCorrupt("computer_ledger_corrupt") from exc
            entries[self._entry_key(entry)] = entry
        return entries

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": LEDGER_SCHEMA,
                   "entries": [asdict(entry) for entry in self._entries.values()]}
        descriptor, temporary = tempfile.mkstemp(prefix=".computer-ledger-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self._lock_path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
        finally:
            handle.close()


__all__ = [
    "ComputerRunLedger",
    "LEDGER_SCHEMA",
    "LedgerCapacity",
    "LedgerCorrupt",
    "LedgerEntry",
    "UNRESOLVED_PHASES",
]
