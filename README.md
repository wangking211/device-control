# Device Control

Independent device-control control plane and gateway for the ai-platform
family. MindOS keeps Task/TaskRun, scheduling and user-facing approval UX;
this service owns device/gateway identity, endpoint inventory, leases, device
policy enforcement, command coordination, adapter lifecycle and evidence
metadata.

**Current milestone:** DC-002 → DC-005 implemented in this repository.

| Area | Status | Evidence |
| --- | --- | --- |
| DC-002 identity, tenant, approval, lease, migration hardening | Implemented, tested | `tests/test_security.py`, `acceptance/ACCEPTANCE-MATRIX.md` |
| DC-003 gateway protocol and lifecycle | Implemented, tested | `tests/test_gateway_protocol.py`, `gateway/tests/` |
| DC-004 Android gateway/adapter | Implemented; hardware acceptance **BLOCKED** (no adb/emulator in this environment) | `gateway/tests/test_adb_adapter.py`, `gateway/tests/test_worker_e2e.py` |
| DC-005 command state machine, idempotency, verification, TaskRun correlation | Implemented, tested | `tests/test_commands.py`, `gateway/tests/test_worker_e2e.py` |
| Docker non-root volume persistence | Configured; **BLOCKED** (Docker unavailable here) | `Dockerfile`, `docker-compose.yml` |

Do not call this production-ready until security, migration, Docker persistence,
real Android device and MindOS end-to-end criteria in
`acceptance/ACCEPTANCE-MATRIX.md` pass.

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
- `acceptance/ACCEPTANCE-MATRIX.md` — PASS/FAIL/BLOCKED with commands.

## Tests

```bash
python -m pytest -q
python -m ruff check src tests gateway/src gateway/tests scripts
python -m mypy src/device_control gateway/src/device_gateway --ignore-missing-imports
```

57 tests pass on Python 3.12 / Windows (2026-11-26). See
`acceptance/ACCEPTANCE-MATRIX.md` for the exact run and blocked hardware items.
