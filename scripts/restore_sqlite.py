"""Verify and restore a Device Control backup into an isolated directory.

    python scripts/restore_sqlite.py --backup /backup/20261126 --target /restore/dry \
        --dry-run
    python scripts/restore_sqlite.py --backup /backup/20261126 --target /restore/prod \
        --evidence-target /data/evidence

The default is a dry run: it verifies the database integrity, the backup
manifest, every Evidence object hash and reports orphan objects. It never
overwrites a production database unless ``--apply`` is passed (and even then the
target must be empty).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--evidence-target", default="")
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--apply", dest="dry_run", action="store_false")
    args = parser.parse_args()

    backup = Path(args.backup)
    target = Path(args.target)
    manifest = json.loads((backup / "backup-manifest.json").read_text(encoding="utf-8"))
    db = backup / "device-control.sqlite3"
    report: dict[str, object] = {"dry_run": args.dry_run, "backup": str(backup)}
    problems: list[str] = []

    if not db.is_file():
        problems.append("database_missing")
    elif sha256(db) != manifest.get("database_sha256"):
        problems.append("database_hash_mismatch")
    else:
        with sqlite3.connect(db) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                problems.append(f"integrity:{integrity}")
            rows = connection.execute(
                "SELECT tenant_ref, storage_ref, content_sha256, size_bytes FROM device_evidence"
                " WHERE deleted_at IS NULL"
            ).fetchall()
        evidence_root = backup / "evidence"
        missing, corrupt = [], []
        referenced = set()
        for _tenant, storage_ref, content_sha256, size_bytes in rows:
            referenced.add(storage_ref)
            candidate = evidence_root / storage_ref
            if not candidate.is_file():
                missing.append(storage_ref)
                continue
            if candidate.stat().st_size != size_bytes or sha256(candidate) != content_sha256:
                corrupt.append(storage_ref)
        report.update({
            "evidence_rows": len(rows),
            "missing_objects": missing,
            "corrupt_objects": corrupt,
            "orphan_objects": sorted(
                str(path.relative_to(evidence_root)).replace("\\", "/")
                for path in evidence_root.rglob("*") if path.is_file()
                and str(path.relative_to(evidence_root)).replace("\\", "/") not in referenced
            ),
        })
        if missing:
            problems.append("missing_evidence_objects")
        if corrupt:
            problems.append("corrupt_evidence_objects")

    report["problems"] = problems
    report["ok"] = not problems
    if not args.dry_run and not problems:
        if target.exists() and any(target.iterdir()):
            raise SystemExit("refusing to overwrite a non-empty restore target")
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(db, target / "device-control.sqlite3")
        evidence_target = Path(args.evidence_target) if args.evidence_target else target / "evidence"
        shutil.copytree(backup / "evidence", evidence_target, dirs_exist_ok=True)
        report["restored_to"] = str(target)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
