"""Consistent SQLite + evidence backup with integrity verification.

    python scripts/backup_sqlite.py --db /data/device-control.sqlite3 \
        --out /backup/device-control-20261126 --evidence /data/evidence

The online backup API is used so a running service can be backed up. The tool
writes a manifest with hashes so a restore can be verified before cutover.
Secrets are not stored in the database (only credential digests), and evidence
objects are copied as-is; encrypt the backup target at rest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--evidence", default="")
    args = parser.parse_args()

    source = Path(args.db)
    target_dir = Path(args.out)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_db = target_dir / "device-control.sqlite3"
    with sqlite3.connect(source) as src, sqlite3.connect(target_db) as dst:
        src.backup(dst)
        check = dst.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise SystemExit(f"integrity check failed: {check}")
        counts = {
            table: dst.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("device_endpoints", "device_gateways", "device_commands", "device_evidence")
            if dst.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
        }

    evidence_manifest = {}
    if args.evidence:
        source_evidence = Path(args.evidence)
        target_evidence = target_dir / "evidence"
        if source_evidence.exists():
            shutil.copytree(source_evidence, target_evidence, dirs_exist_ok=True)
            for path in sorted(target_evidence.rglob("*")):
                if path.is_file():
                    evidence_manifest[str(path.relative_to(target_evidence))] = sha256(path)

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database_sha256": sha256(target_db),
        "counts": counts,
        "evidence": evidence_manifest,
    }
    (target_dir / "backup-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
