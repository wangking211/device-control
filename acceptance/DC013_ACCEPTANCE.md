# DC-013 Acceptance Matrix

Date: 2026-11-27. Device-control `c0c3923` base; MindOS `0e9010cc`; ai-platform
local `f0ce6f7` / origin `0b80eec`. No Docker daemon, live HA, Android device or
MindOS runtime in this environment. 126 tests pass locally; Ruff/mypy/Bandit
clean; pip-audit no known vulnerabilities.

| ID | Requirement | Priority | Status | Evidence |
|---|---|---:|---|---|
| D13-001 | Security CI / no unhandled dependency findings | P0 | PASS (local) / BLOCKED (remote CI/containers) | Pillow 13.0.0; `docs/DC013_01_SECURITY_REPORT.md`; pip-audit clean |
| D13-002 | Worker write safety: mandatory state, mapping, freshness | P0 | PASS | worker rejects missing/stale/mismatched state; no HA POST in negative tests |
| D13-003 | HA WebSocket auth/reconnect/dedupe/compensation | P1 | PARTIAL | `websocket.py` client/deduper/backoff/classify tests; not wired to ingestion; live BLOCKED |
| D13-004 | Telemetry/Twin persistence, dedupe, late data | P1 | PASS (synthetic) | migration 9, telemetry API, dedupe/late twin tests |
| D13-005 | MindOS Provider Registry + real TaskRun | P0 | BLOCKED | provider module only; no live MindOS runtime/TaskRun |
| D13-006 | Device management UI minimal loop | P1 | PARTIAL | existing `/admin` shell; platform/device APIs; no dedicated claim/authorize UI |
| D13-007 | Docker + real Home Assistant E2E | P0 | BLOCKED | `docker-compose.ha.yml`, non-root worker image, runbook; no Docker/HA here |
| D13-008 | Android controlled live E2E | P1 | BLOCKED | no adb/emulator/device; prior Android path exists |
| D13-009 | Success only after state/Evidence verification | P0 | PASS (synthetic) | HA state read-back and `executed_unverified`; existing command verification |
| D13-010 | Audit correlation task/command/device/approval/evidence | P0 | PASS (synthetic) | command refs/audit tests; live TaskRun/Evidence BLOCKED |
| D13-011 | Real write operations disabled until P0 gates | P0 | PASS | production platform creation disabled; worker not configured with real HA |

## Gate

Local P0 code/security tests pass, but remote CI, Docker/HA E2E, live MindOS
TaskRun and Android E2E are BLOCKED. Real device writes remain disabled; overall
**NO-GO**.
