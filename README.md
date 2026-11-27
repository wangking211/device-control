# Device Control

Independent device-control control plane and gateway for the ai-platform
family. MindOS keeps Task/TaskRun, scheduling and user-facing approval UX;
this service owns device/gateway identity, endpoint inventory, leases, device
policy enforcement, command coordination, adapter lifecycle and evidence
metadata.

**Current milestone:** DC-002 → DC-009 implemented in this repository.

| Area | Status | Evidence |
| --- | --- | --- |
| DC-002 identity, tenant, approval, lease, migration hardening | Implemented, tested | `tests/test_security.py`, `acceptance/ACCEPTANCE-MATRIX.md` |
| DC-003 gateway protocol and lifecycle | Implemented, tested | `tests/test_gateway_protocol.py`, `gateway/tests/` |
| DC-004 Android gateway/adapter | Implemented; hardware acceptance **BLOCKED** | `gateway/tests/test_adb_adapter.py`, `gateway/tests/test_worker_e2e.py` |
| DC-005 command state machine, idempotency, verification | Implemented, tested | `tests/test_commands.py` |
| DC-006 manifest authority, device binding, approval v2, hard timeout | Implemented, tested | `tests/test_gateway_protocol.py`, `gateway/tests/test_preflight.py`, `gateway/tests/test_isolation.py` |
| DC-007 Accessibility state, Evidence service, diagnostics | Implemented; real device/durable object store **BLOCKED** | `tests/test_evidence.py`, `docs/EVIDENCE_STORE.md` |
| DC-008 OpenAPI, MindOS provider and contract mapping | Implemented; live MindOS E2E **BLOCKED** | `contracts/openapi-v1.json`, `examples/mindos_provider.py`, `tests/test_mindos_contract.py` |
| DC-009 production guardrails, backup/upgrade/preflight, admin/alerts | Implemented; Docker/TLS/mTLS **BLOCKED** | `scripts/`, `docs/PRODUCTION_READINESS.md` |
| DC-010 redaction/policy/state/Ed25519/evidence DI | Implemented; live Android/Docker/MindOS **BLOCKED** | `acceptance/DC010_ACCEPTANCE.md` |
| DC-011 IoT platform integration architecture | Design/contracts/SPI implemented; live platforms **BLOCKED** | `docs/ADR-003-IOT-INTEGRATION.md`, `tests/test_iot_spi.py` |

Do not call this production-ready until security, migration, Docker persistence,
real Android device and MindOS end-to-end criteria in
`acceptance/ACCEPTANCE-MATRIX.md` pass. The overall decision is **NO-GO** while
hardware/Docker/MindOS rows are BLOCKED.

## Quick start (local)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
export MINDOS_IDENTITY_HMAC_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export MINDOS_IDENTITY_ISSUER=mindos-local
export DEVICE_CONTROL_ADMIN_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export DEVICE_CONTROL_DB=./var/device-control.sqlite3
uvicorn device_control.app:app --app-dir src --port 8085
```

- Bootstrap token: local provisioning only. Production (`DEVICE_CONTROL_ENV=production`)
  rejects it and requires platform-issued HS256 identities.
- Mint a local test token: `python scripts/mint_local_token.py --subject agent-1 --tenant tenant-a --permission device.endpoint.read`.
- Enroll a gateway: `python scripts/bootstrap_gateway.py --control-url http://127.0.0.1:8085 --admin-token "$DEVICE_CONTROL_ADMIN_TOKEN" --tenant tenant-a --gateway gateway-a`.

## Gateway (separately deployable)

```bash
pip install -e ./gateway
export DEVICE_CONTROL_URL=http://127.0.0.1:8085
export DEVICE_GATEWAY_ID=gateway-a
export DEVICE_GATEWAY_CREDENTIAL=<one-time credential from bootstrap>
export DEVICE_GATEWAY_ADAPTER=fake        # or android
export DEVICE_GATEWAY_ALLOWED_APPS=com.example.notes
python -m device_gateway.main --once
```

ADB path and serial come from operator configuration
(`DEVICE_GATEWAY_ADB_PATH`, `DEVICE_GATEWAY_SERIAL`); they are never accepted
from a command envelope. ADB never runs in this FastAPI process.

## Documentation

- `docs/ARCHITECTURE.md` — components, trust boundaries, data flow.
- `docs/DC-002-SECURITY-AUTH.md` — principals, scopes, approvals, tenant isolation.
- `docs/DC-003-GATEWAY-PROTOCOL.md` — lifecycle, transport, lifecycle endpoints.
- `docs/DC-004-ANDROID-GATEWAY.md` — adapter capabilities, exclusions, support matrix.
- `docs/DC-005-COMMAND-EXECUTION.md` — state machine, idempotency, verification, events.
- `docs/API.md` — HTTP surface.
- `docs/MINDOS-INTEGRATION.md` — TaskRun correlation and failure isolation.
- `docs/OPERATIONS.md` — migrations, volumes, rotation, maintenance.
- `docs/ADR-001-DEVICE-CONTROL-STATE.md` — new-table/endpoint/abstraction justification.
- `docs/ADR-002-DC006-009-MANIFEST-EVIDENCE.md` — manifest authority, device binding, evidence.
- `docs/security/` — execution threat model and approval/replay analysis.
- `docs/android/` — UI state/verification and real-device runbook.
- `docs/EVIDENCE_STORE.md`, `docs/PRODUCTION_READINESS.md` — evidence and operations.
- `docs/contracts/MINDOS_DEVICE_INTENT_MAPPING.md` — MindOS field/status/error mapping.
- `docs/BASELINE_AUDIT.md` — DC-006…DC-009 baseline audit and blockers.
- `acceptance/DC010_ACCEPTANCE.md` — DC-010 P0/P1 matrix and NO-GO blockers.
- `docs/DC011_BASELINE.md`, `docs/ADR-003-IOT-INTEGRATION.md` — IoT platform boundary.
- `docs/OPEN_SOURCE_PLATFORM_RESEARCH.md`, `docs/PLATFORM_SELECTION_MATRIX.md` — verified platform facts.
- `docs/IOT_ADAPTER_SPI.md`, `docs/HOME_ASSISTANT_PILOT.md` — adapter and pilot spec.
- `acceptance/DC011_ACCEPTANCE.md` — design gate status and blockers.
- `docs/DC010_REBASELINE.md` — real SHAs, interfaces and ownership.
- `docs/security/SCREENSHOT_REDACTION.md` — redaction pipeline and limits.
- `docs/MANIFEST_KEY_MANAGEMENT.md` — Ed25519 key generation/rotation.
- `acceptance/GO_NO_GO.md` — current NO-GO decision and remaining gates.
- `acceptance/ACCEPTANCE-MATRIX.md` — PASS/FAIL/BLOCKED with commands.

## Tests

```bash
python -m pytest -q
python -m ruff check src tests gateway/src gateway/tests scripts
python -m mypy src/device_control gateway/src/device_gateway --ignore-missing-imports
```

114 tests pass on Python 3.12 / Windows (2026-11-27). See
`acceptance/ACCEPTANCE-MATRIX.md` for the exact run and blocked hardware items.
