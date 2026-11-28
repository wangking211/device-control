# DC-014 HA WebSocket Durable Ingestion and Telemetry Convergence

Tasks: 014-05 (P0), 014-06 (P1). Repo: `device-control`.

## What is durable now

`HomeAssistantEventPipeline` (`src/device_control/iot/adapters/ingest.py`) turns
the existing WebSocket primitives into a persisted pipeline:

| Requirement | Implementation |
|---|---|
| Subscription lifecycle / secret resolver | `build_websocket()` maps HTTPS→WSS and HTTP→WS; the token is supplied by the caller's secret resolver, never stored in the DB |
| Persisted cursor and connection state | `ha_ingest_state` (one row per tenant/platform) |
| Only claimed tenant/platform entities | `claimed_entity_map()` plus a store-level recheck of `iot_devices.trust_state='claimed'` |
| Normalized versioned event | `ha_event_log.schema_version='1'`, normalized `event_key` |
| Dedupe identity | context + entity + state + relevant-attribute digest + `last_updated` |
| Persist before cursor advance | event log, telemetry, twin and cursor commit in one `BEGIN IMMEDIATE` transaction |
| Reconnect reconciliation + gap marker | `reconcile()` performs REST read-back, writes `iot.event.gap`, updates `gap_count`/`last_reconcile_at` |
| Metrics | connected, last_event_at, last_reconcile_at, duplicate_count, gap_count, reconnect_count, lag_seconds |
| Token invalid vs transient | `PermissionError` is re-raised (no retry); `ConnectionClosed`/`OSError` use bounded backoff |
| TLS | `ssl.SSLContext` still used for `wss://`; no `verify_mode=CERT_NONE` |

## Telemetry / Twin convergence

- `observed_at` (source) and `received_at` (edge) are separate columns/fields.
- `event_key` = digest(context, entity, state, relevant attributes, last_updated).
  `friendly_name`/`icon` are excluded so cosmetic churn does not create events;
  any other attribute change is a distinct event.
- Late/out-of-order events stay queryable but cannot roll the twin back:
  `_keep_newer` compares `observed_at`.
- Future timestamps beyond 300 s are clamped to receive time and marked
  `status=time_skew`, `quality=suspect`; the twin is not pinned into the future.
- `desired`, `reported`, `observed`, `quality` and `connectivity` remain
  distinct fields.
- Freshness is per device type (`sensor` 60 s, `light`/`switch` 300 s, default
  300 s) and exposed as `freshness` on `GET /v1/iot-devices/{id}/twin`.

## API

- `GET /v1/platform-instances/{id}/ingest-state` — tenant-scoped metrics.
- `GET /v1/platform-instances/{id}/events?device_id=&limit=` — bounded,
  tenant-scoped persisted events.
- `GET /v1/iot-devices/{id}/twin` — now includes `freshness`.

Both platform endpoints return 404 for another tenant.

## Tests

`tests/test_ha_ingest.py` (12 tests) covers persistence, duplicate replay,
attribute-only changes, unclaimed entities, late/out-of-order events, future
skew, reconnect reconciliation and gap markers, auth-invalid stop, metrics,
cross-tenant rejection and per-device freshness. `tests/test_ha_websocket.py`
covers the dedupe/backoff primitives.

## Not proven here

- A live Home Assistant WebSocket connection: **BLOCKED** (no HA instance in
  this environment).
- Docker + real HA compose E2E: **BLOCKED** (no Docker daemon).
- Crash/restart replay against a live database: covered by deterministic
  duplicate tests, not by a kill-and-restart drill.

No synthetic result is reported as a live PASS.
