"""Durable gateway-side dedupe ledger.

The control plane already enforces per-tenant idempotency. The gateway ledger
protects the device from duplicate delivery across gateway restarts and
reconnects: the same ``command_id`` is executed at most once, and a conflicting
payload under the same key is refused instead of executed.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NEW = "new"
DUPLICATE = "duplicate"
CONFLICT = "conflict"


@dataclass(frozen=True)
class Claim:
    outcome: str
    status: str | None = None
    result: dict[str, Any] | None = None


class DedupeLedger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS gateway_commands ("
            "command_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL, payload_hash TEXT NOT NULL,"
            " status TEXT NOT NULL, result_json TEXT, updated_at TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_idempotency"
            " ON gateway_commands(idempotency_key)"
        )

    def claim(self, command: dict[str, Any]) -> Claim:
        command_id = str(command["command_id"])
        key = str(command["idempotency_key"])
        payload_hash = str(command.get("payload_hash") or self._hash(command))
        row = self._db.execute(
            "SELECT * FROM gateway_commands WHERE command_id=?", (command_id,)
        ).fetchone()
        if row is not None:
            if row["payload_hash"] != payload_hash:
                return Claim(CONFLICT)
            return Claim(DUPLICATE, status=row["status"],
                         result=json.loads(row["result_json"]) if row["result_json"] else None)
        try:
            self._db.execute(
                "INSERT INTO gateway_commands (command_id, idempotency_key, payload_hash,"
                " status, result_json, updated_at) VALUES (?, ?, ?, 'claimed', NULL, ?)",
                (command_id, key, payload_hash, self._now()),
            )
        except sqlite3.IntegrityError:
            existing = self._db.execute(
                "SELECT * FROM gateway_commands WHERE idempotency_key=?", (key,)
            ).fetchone()
            if (existing is not None and existing["command_id"] == command_id
                    and existing["payload_hash"] == payload_hash):
                return Claim(DUPLICATE, status=existing["status"])
            return Claim(CONFLICT)
        return Claim(NEW)

    def complete(self, command_id: str, *, status: str, result: dict[str, Any] | None = None) -> None:
        self._db.execute(
            "UPDATE gateway_commands SET status=?, result_json=?, updated_at=? WHERE command_id=?",
            (status, json.dumps(result, sort_keys=True) if result is not None else None,
             self._now(), command_id),
        )

    def is_terminal(self, command_id: str) -> bool:
        row = self._db.execute(
            "SELECT status FROM gateway_commands WHERE command_id=?", (command_id,)
        ).fetchone()
        return bool(row and row["status"] in {"succeeded", "failed", "rejected", "timed_out",
                                              "cancelled", "uncertain"})

    def pending_results(self) -> list[tuple[str, dict[str, Any]]]:
        rows = self._db.execute(
            "SELECT command_id, result_json FROM gateway_commands WHERE status='result_pending'"
        ).fetchall()
        return [
            (row["command_id"], json.loads(row["result_json"]))
            for row in rows if row["result_json"]
        ]

    def close(self) -> None:
        self._db.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _hash(command: dict[str, Any]) -> str:
        import hashlib

        payload = {key: command.get(key) for key in (
            "capability_id", "capability_version", "parameters", "intent", "deadline", "state_hash"
        )}
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
