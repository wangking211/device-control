import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def run(script, *args, env=None):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=ROOT, text=True, capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def test_sqlite_backup_and_integrity_manifest(tmp_path):
    db = tmp_path / "device-control.sqlite3"
    import sqlite3

    connection = sqlite3.connect(db)
    connection.execute(
        "CREATE TABLE device_evidence (id TEXT PRIMARY KEY, tenant_ref TEXT,"
        " storage_ref TEXT, content_sha256 TEXT, size_bytes INTEGER, deleted_at TEXT)"
    )
    connection.commit()
    connection.close()
    out = tmp_path / "backup"
    result = run("backup_sqlite.py", "--db", str(db), "--out", str(out))
    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "backup-manifest.json").read_text())
    assert manifest["database_sha256"]
    assert manifest["counts"]["device_evidence"] == 0
    assert (out / "device-control.sqlite3").is_file()

    dry = run("restore_sqlite.py", "--backup", str(out), "--target", str(tmp_path / "restore"))
    assert dry.returncode == 0, dry.stdout
    assert json.loads(dry.stdout)["dry_run"] is True


def test_signed_upgrade_is_verified_or_rejected(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    package = tmp_path / "gateway.tar.gz"
    package.write_bytes(b"release-bytes")
    signature = private_key.sign(package.read_bytes())
    signature_path = tmp_path / "gateway.tar.gz.sig"
    signature_path.write_bytes(base64.b64encode(signature))
    public_path = tmp_path / "release-public.pem"
    public_path.write_bytes(public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    accepted = run("verify_upgrade.py", "--package", str(package),
                   "--signature", str(signature_path), "--public-key", str(public_path))
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    package.write_bytes(b"tampered")
    rejected = run("verify_upgrade.py", "--package", str(package),
                   "--signature", str(signature_path), "--public-key", str(public_path))
    assert rejected.returncode == 1


def test_gateway_preflight_blocks_insecure_transport(tmp_path):
    env = {
        "DEVICE_CONTROL_URL": "http://example.com",
        "DEVICE_GATEWAY_CREDENTIAL": "x" * 40,
        "DEVICE_GATEWAY_ADAPTER": "fake",
        "DEVICE_GATEWAY_DB": str(tmp_path / "gateway.sqlite3"),
    }
    failed = run("gateway_preflight.py", "--json", env=env)
    assert failed.returncode == 1
    result = json.loads(failed.stdout)
    assert any(item["code"] == "control_url_transport" and not item["ok"]
               for item in result["checks"])

    env["DEVICE_CONTROL_URL"] = "http://127.0.0.1:8085"
    passed = run("gateway_preflight.py", "--json", env=env)
    assert passed.returncode == 0, passed.stdout
