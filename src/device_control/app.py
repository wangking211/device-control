from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "contracts" / "v1"
SCHEMAS = {
    "endpoint": "device-endpoint.schema.json",
    "invocation": "device-invocation.schema.json",
    "result": "device-result.schema.json",
}


def load_schema(name: str) -> dict[str, Any]:
    filename = SCHEMAS.get(name)
    if filename is None:
        raise KeyError(name)
    return json.loads((CONTRACT_DIR / filename).read_text(encoding="utf-8"))


def validate_contract(name: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    schema = load_schema(name)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    return [
        {"path": "/" + "/".join(map(str, error.absolute_path)), "message": error.message}
        for error in errors
    ]


app = FastAPI(
    title="Device Control API",
    version="0.1.0",
    description=(
        "Independent device-control boundary. Device execution endpoints are not enabled "
        "until authenticated endpoint enrollment and policy enforcement are configured."
    ),
)


@app.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready", tags=["health"])
def ready() -> dict[str, str]:
    missing = [filename for filename in SCHEMAS.values() if not (CONTRACT_DIR / filename).is_file()]
    if missing:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "missing_contracts": missing})
    return {"status": "ready", "contract_version": "v1"}


@app.get("/v1/contracts", tags=["contracts"])
def contract_catalog() -> dict[str, Any]:
    return {
        "version": "v1",
        "contracts": [
            {"name": name, "schema": f"/v1/contracts/{name}"} for name in SCHEMAS
        ],
    }


@app.get("/v1/contracts/{name}", tags=["contracts"])
def get_contract(name: str) -> dict[str, Any]:
    try:
        return load_schema(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract_not_found") from exc


@app.post("/v1/contracts/{name}/validate", tags=["contracts"])
def validate(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name not in SCHEMAS:
        raise HTTPException(status_code=404, detail="contract_not_found")
    errors = validate_contract(name, payload)
    return {"valid": not errors, "errors": errors, "contract_version": "v1"}
