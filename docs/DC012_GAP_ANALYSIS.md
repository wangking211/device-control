# DC-012 Gap Analysis

| Area | Current | Gap / next |
| --- | --- | --- |
| Platform instance | table/API/health fields | signed production provisioning; real adapter worker deploy |
| Discovery | REST `/api/states`, stable `(tenant, instance, native_id)` upsert | HA device/area/entity registry via stable public API; rename/delete reconciliation |
| Claim | pending→claimed; default read-only; explicit write capability | claim UI/MindOS confirmation; unpair/revoke; capability item approval UX |
| Command | existing lease/approval/manifest/state/idempotency pipeline; HA worker | live HA action verification, timeout/cancel races, HA restart |
| WebSocket | not implemented; `subscribe` returns empty | auth state machine, subscribe/resubscribe, duplicate/out-of-order/replay |
| Telemetry/Twin | twin separate desired/reported/observed API; adapter get_telemetry | event-driven ingest, cursor, quality/clock drift; no DB telemetry pipeline |
| Security | secret refs, TLS config, allowlist, read-back; no arbitrary service | production signed manifest gate, rate limit, cross-tenant live tests |
| MindOS | provider module/descriptor + contract tests | live registry registration, TaskRun UI/approval/evidence E2E |
| Tests | synthetic HA fake transport E2E | real HA instance, TLS/auth failures, network/HA restart, WS replay |
| Evidence | command result/audit; no HA action evidence | optional screenshot/state evidence for HA actions (not applicable to all) |

## Duplicate-building risks

- Do not create a second command engine: HA commands use `/v1/commands` and the
  existing state machine.
- Do not create a second provider runtime: MindOS provider descriptor uses the
  existing registry.
- Do not copy HA state into a parallel safety model: twin observed/reported and
  telemetry are observational, not control authority.
- Do not add a second MQTT/queue: HA REST/WS is the pilot; MQTT remains optional
  adapter transport.
