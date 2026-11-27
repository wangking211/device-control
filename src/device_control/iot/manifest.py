"""Adapter plugin manifest loading, schema validation and provenance checks."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "contracts" / "v1" / "adapter-plugin-manifest.schema.json"
SUPPORTED_API_VERSIONS = frozenset({"1.0"})


@dataclass(frozen=True)
class AdapterManifest:
    raw: dict[str, Any]

    @property
    def adapter_id(self) -> str:
        return str(self.raw["adapter_id"])

    @property
    def version(self) -> str:
        return str(self.raw["version"])

    @property
    def api_version(self) -> str:
        return str(self.raw["api_version"])

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.api_version not in SUPPORTED_API_VERSIONS:
            errors.append(f"unsupported adapter api_version: {self.api_version}")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        for error in Draft202012Validator(schema).iter_errors(self.raw):
            errors.append(f"{'/'.join(map(str, error.absolute_path)) or '/'}: {error.message}")
        credential_schema = self.raw.get("credential_schema")
        if isinstance(credential_schema, dict) and credential_schema and \
                "secret_ref" not in json.dumps(credential_schema):
            errors.append("credential_schema must reference secrets, not literal values")
        return errors


def load_manifest(path: str | Path) -> AdapterManifest:
    return AdapterManifest(json.loads(Path(path).read_text(encoding="utf-8")))


def verify_manifest(manifest: AdapterManifest, public_key_pem: str,
                    allowed_key_ids: set[str] | None = None) -> bool:
    signature = manifest.raw.get("signature")
    if not isinstance(signature, dict):
        return False
    if allowed_key_ids and signature.get("key_id") not in allowed_key_ids:
        return False
    if signature.get("algorithm") != "Ed25519":
        return False
    payload = {key: value for key, value in manifest.raw.items() if key != "signature"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(public_key_pem.encode())
        key.verify(base64.b64decode(str(signature["value"])), canonical)  # type: ignore[call-arg]
        return True
    except Exception:  # noqa: BLE001 - fail closed
        return False
