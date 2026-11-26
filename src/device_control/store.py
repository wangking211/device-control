from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def database_path() -> Path:
    return Path(os.environ.get("DEVICE_CONTROL_DB", "./var/device-control.sqlite3"))


def connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("""CREATE TABLE IF NOT EXISTS device_endpoints (
        endpoint_id TEXT PRIMARY KEY,
        tenant_ref TEXT NOT NULL,
        node_ref TEXT,
        credential_hash TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('online','degraded','offline','revoked')),
        capabilities_json TEXT NOT NULL,
        observed_at TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS device_leases (
        lease_id TEXT PRIMARY KEY,
        endpoint_id TEXT NOT NULL REFERENCES device_endpoints(endpoint_id),
        tenant_ref TEXT NOT NULL,
        task_ref TEXT NOT NULL,
        run_ref TEXT,
        holder_ref TEXT NOT NULL,
        mode TEXT NOT NULL CHECK(mode IN ('read_only','control')),
        expires_at TEXT NOT NULL,
        released_at TEXT
    )""")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_device_active_lease ON device_leases(endpoint_id) WHERE released_at IS NULL")
    return db


def hash_credential(credential: str) -> str:
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def enroll(*, endpoint_id: str, tenant_ref: str, node_ref: str | None,
           capabilities: list[dict[str, Any]], observed_at: str) -> str:
    credential = secrets.token_urlsafe(32)
    with connect() as db:
        db.execute(
            "INSERT INTO device_endpoints VALUES (?, ?, ?, ?, 'offline', ?, ?)",
            (endpoint_id, tenant_ref, node_ref, hash_credential(credential),
             json.dumps(capabilities), observed_at),
        )
    return credential


def get_endpoint(endpoint_id: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
    if row is None:
        return None
    return {
        "endpoint_id": row["endpoint_id"], "tenant_ref": row["tenant_ref"],
        "node_ref": row["node_ref"], "status": row["status"],
        "capabilities": json.loads(row["capabilities_json"]), "observed_at": row["observed_at"],
        "credential_hash": row["credential_hash"],
    }


def list_endpoints(tenant_ref: str) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT endpoint_id, tenant_ref, node_ref, status, capabilities_json, observed_at "
            "FROM device_endpoints WHERE tenant_ref=? ORDER BY endpoint_id", (tenant_ref,),
        ).fetchall()
    return [{"endpoint_id": r["endpoint_id"], "tenant_ref": r["tenant_ref"],
             "node_ref": r["node_ref"], "status": r["status"],
             "capabilities": json.loads(r["capabilities_json"]), "observed_at": r["observed_at"]}
            for r in rows]


def authenticate(endpoint_id: str, credential: str) -> bool:
    endpoint = get_endpoint(endpoint_id)
    return bool(endpoint and endpoint["status"] != "revoked" and secrets.compare_digest(
        endpoint["credential_hash"], hash_credential(credential)))


def heartbeat(endpoint_id: str, *, status: str, capabilities: list[dict[str, Any]], observed_at: str) -> None:
    with connect() as db:
        db.execute("UPDATE device_endpoints SET status=?, capabilities_json=?, observed_at=? WHERE endpoint_id=?",
                   (status, json.dumps(capabilities), observed_at, endpoint_id))


def revoke(endpoint_id: str) -> bool:
    with connect() as db:
        cursor = db.execute("UPDATE device_endpoints SET status='revoked' WHERE endpoint_id=?", (endpoint_id,))
        db.execute("UPDATE device_leases SET released_at=? WHERE endpoint_id=? AND released_at IS NULL",
                   (datetime.now(timezone.utc).isoformat(), endpoint_id))
        return cursor.rowcount > 0


def acquire_lease(*, lease_id: str, endpoint_id: str, tenant_ref: str, task_ref: str,
                  run_ref: str | None, holder_ref: str, mode: str, expires_at: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        endpoint = db.execute("SELECT status, tenant_ref FROM device_endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
        if endpoint is None or endpoint["tenant_ref"] != tenant_ref or endpoint["status"] in {"offline", "revoked"}:
            return None
        db.execute("UPDATE device_leases SET released_at=? WHERE endpoint_id=? AND released_at IS NULL AND expires_at<=?",
                   (now, endpoint_id, now))
        try:
            db.execute("INSERT INTO device_leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                       (lease_id, endpoint_id, tenant_ref, task_ref, run_ref, holder_ref, mode, expires_at))
        except sqlite3.IntegrityError:
            active = db.execute("SELECT * FROM device_leases WHERE endpoint_id=? AND released_at IS NULL", (endpoint_id,)).fetchone()
            return {"conflict": True, "holder_ref": active["holder_ref"], "task_ref": active["task_ref"]} if active else None
    return {"lease_id": lease_id, "endpoint_id": endpoint_id, "tenant_ref": tenant_ref,
            "task_ref": task_ref, "run_ref": run_ref, "holder_ref": holder_ref,
            "mode": mode, "expires_at": expires_at}


def release_lease(lease_id: str, tenant_ref: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        cursor = db.execute("UPDATE device_leases SET released_at=? WHERE lease_id=? AND tenant_ref=? AND released_at IS NULL",
                            (now, lease_id, tenant_ref))
        return cursor.rowcount > 0
