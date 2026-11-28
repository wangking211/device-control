"""Durable local action ledger for Computer Runtime restart recovery."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_SCHEMA = "dc.computer-ledger/v1"
MAX_ENTRIES = 500


class LedgerCorrupt(RuntimeError):
    pass


@dataclass
class LedgerEntry:
    schema: str
    tenant_ref: str
    endpoint_id: str
    idempotency_key: str
    fingerprint: str
    phase: str  # executing | completed | unknown
    command_id: str
    result: dict[str, Any] | None = None
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ComputerRunLedger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path(
            os.environ.get("COMPUTER_RUNTIME_LEDGER") or "./var/computer-ledger.json"
        )
        self._entries: dict[str, LedgerEntry] = {}
        self._load()

    @staticmethod
    def key(tenant_ref: str, endpoint_id: str, idempotency_key: str) -> str:
        return "|".join((tenant_ref, endpoint_id, idempotency_key))

    def get(self, key: str) -> LedgerEntry | None:
        return self._entries.get(key)

    def record(self, entry: LedgerEntry) -> None:
        previous = self._entries.get(entry.tenant_ref + "|" + entry.endpoint_id + "|" + entry.idempotency_key)
        if previous and previous.fingerprint != entry.fingerprint:
            raise RuntimeError("computer_ledger_fingerprint_conflict")
        self._entries[ComputerRunLedger.key(entry.tenant_ref, entry.endpoint_id,
                                            entry.idempotency_key)] = entry
        self._trim()
        self._persist()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LedgerCorrupt("computer_ledger_corrupt") from exc
        if not isinstance(data, dict) or data.get("schema") != LEDGER_SCHEMA:
            raise LedgerCorrupt("computer_ledger_corrupt")
        for item in data.get("entries") or []:
            try:
                entry = LedgerEntry(**item)
            except TypeError as exc:
                raise LedgerCorrupt("computer_ledger_corrupt") from exc
            self._entries[ComputerRunLedger.key(entry.tenant_ref, entry.endpoint_id,
                                                entry.idempotency_key)] = entry

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": LEDGER_SCHEMA,
                   "entries": [asdict(entry) for entry in self._entries.values()]}
        descriptor, temporary = tempfile.mkstemp(prefix=".computer-ledger-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _trim(self) -> None:
        if len(self._entries) <= MAX_ENTRIES:
            return
        completed = sorted(
            ((key, entry) for key, entry in self._entries.items()
             if entry.phase != "executing"),
            key=lambda item: item[1].updated_at,
        )
        for key, _ in completed:
            if len(self._entries) <= MAX_ENTRIES:
                break
            self._entries.pop(key, None)


__all__ = ["ComputerRunLedger", "LEDGER_SCHEMA", "LedgerCorrupt", "LedgerEntry"]
