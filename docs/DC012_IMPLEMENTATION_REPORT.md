# DC-012 Implementation Report

Date: 2026-11-27. Baseline: device-control `d084475`, mind-os `0e9010cc`,
ai-platform local `932cc0a` / origin `592c71b`.

## Delivered

- Migration 8: `platform_instances`, `iot_devices`, `iot_twins`.
- APIs: platform create/list/detail/disable/discover; IoT device list/detail/
  claim; twin get/update.
- Platform creation also provisions an internal HA gateway/manifest and returns
  its one-time adapter credential; production creation is disabled until the
  signed manifest/DC-010 workflow is approved.
- Claim creates a Device Control endpoint for the claimed entity with explicit
  capabilities; default is read-only. Unclaimed devices have no endpoint.
- HA adapter remains REST + read-back; the pilot worker pulls existing
  `/v1/gateways/{id}/commands`, enforces entity/capability allowlists and state
  hash, executes via HA service, re-reads state, and posts explicit verification.
- Operator worker entrypoint: `scripts/ha_adapter_worker.py` (secret injected by
  the process environment; no CLI token).
- Synthetic E2E test covers platform → discovery → claim → lease/approval →
  command → worker execution → verified status; sensor telemetry and twin
  separation are covered.
- Tenant isolation and default read-only tests.

## Test results

```
pytest -q                       120 passed
ruff check ...                  All checks passed
mypy ...                        Success: no issues (38 files)
bandit ...                      0 issues
```

## Not delivered / blocked

- Live Home Assistant instance, real token, real service call, HA restart.
- WebSocket auth/subscription/reconnect/duplicate/out-of-order/replay.
- MindOS live TaskRun UI/approval/evidence E2E.
- Telemetry/event ingestion pipeline, cursor persistence and backpressure.
- Production signed platform manifest/worker deployment, TLS/mTLS, Docker.
- DC-010 real Android/Docker/MindOS gates remain NO-GO.

## Decision

Isolated pilot PASS; production/IoT **NO-GO**. No real HA credential or device
was used, and accepted service responses are not reported as verified unless the
state is re-read and matches.
