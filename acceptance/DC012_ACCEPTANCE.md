# DC-012 Acceptance Matrix

Date: 2026-11-27. Environment: Windows, Python 3.12.9, pytest 9.1.1, no live
Home Assistant, no HA token, no Docker, no real device. Synthetic fake-transport
pilot only. Automated suite count: **120 passed**; Ruff/mypy/Bandit clean.

| ID | Requirement | Priority | Status | Evidence |
|---|---|---:|---|---|
| D12-001 | DC-010/DC-011 prerequisite gates | P0 | PARTIAL/BLOCKED | DC-011 design PASS; DC-010 production gates NO-GO, so real HA writes blocked |
| D12-002 | Adapter uses existing SPI | P0 | PASS | `HomeAssistantAdapter` implements `AdapterPlugin`; `test_home_assistant_adapter.py` |
| D12-003 | HA credential Secret Reference | P0 | PASS | platform `secret_ref` + adapter resolver; token never in repr/log; test |
| D12-004 | TLS/auth/health/error classification | P0 | PASS (unit) | HTTPS validation, HTTP 401 `authentication_failed`, health test |
| D12-005 | Discovery/stable mapping | P1 | PASS (synthetic) | platform discover API + `(tenant, instance, native_id)` upsert; tests |
| D12-006 | Unclaimed device not writable | P0 | PASS | unclaimed has no endpoint; default claim read-only; write command 409 |
| D12-007 | Capability allowlist/parameter validation | P0 | PASS | HA capability allowlist, manifest schema, `ha_pilot.native_command`; tests |
| D12-008 | REST/WS state/events | P1 | PARTIAL | REST discovery/observe; WebSocket not implemented |
| D12-009 | HA state write API not used for control | P0 | PASS | adapter only uses `/api/services/*`; no `/api/states` POST |
| D12-010 | Approval before action | P0 | PASS | control-plane approval/lease/command test; worker only pulls authorized commands |
| D12-011 | Idempotency/retry/cancel/timeout | P0 | PARTIAL | existing command/idempotency/cancel tests; HA worker no retry/uncertain replay |
| D12-012 | accepted not verified | P0 | PASS | service 2xx + unchanged state → `executed_unverified`; test |
| D12-013 | MindOS TaskRun Provider E2E | P1 | BLOCKED | provider module/descriptor only; no live MindOS runtime |
| D12-014 | Tenant/credential/event isolation | P0 | PASS (unit) | platform/device cross-tenant 404; secret ref; evidence/tenant tests |
| D12-015 | HA restart/network/WS recovery | P1 | BLOCKED | no live HA; WS not implemented |
| D12-016 | Test light + temperature sensor pilot | P1 | PASS (synthetic) / BLOCKED (live) | fake HA discovery/claim/light command/read-back + sensor telemetry tests |

## Gate decision

Synthetic pilot and P0 device-control checks PASS; **live HA/MindOS/TLS/Docker
and WebSocket recovery remain BLOCKED**. Real HA write operations must stay
disabled until DC-010 P0 gates pass and D12-008/013/015/016 live rows are
executed. Overall: **NO-GO for production**, design/isolated implementation only.
