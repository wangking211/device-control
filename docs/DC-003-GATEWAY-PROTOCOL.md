# DC-003 — Gateway Protocol & Lifecycle

Status: **implemented and tested** for the HTTP protocol; TLS/mTLS deployment
is a deployment concern (see hardening below).

## Lifecycle

```
unregistered → enrollment_pending → trusted → online ↔ degraded → offline → revoked
```

- `POST /v1/gateways` creates `enrollment_pending` and returns a one-time
  enrollment token (TTL `DEVICE_CONTROL_ENROLLMENT_TTL_SECONDS`, default 300s).
- `POST /v1/gateways/{id}/activate` exchanges it for an access credential.
  Replay is rejected. The enrollment credential is revoked at activation.
- Heartbeat moves `trusted → online/degraded/offline`. A heartbeat older than
  `DEVICE_CONTROL_STALE_AFTER_SECONDS` (default 90s) is marked offline by
  maintenance.
- `DELETE /v1/gateways/{id}` revokes the gateway and its credentials, releases
  leases, invalidates approvals and cancels/uncertains pending commands for its
  endpoints.
- `POST /v1/gateways/{id}/credentials/rotate` revokes old access credentials and
  issues a new one.

Gateway identity is distinct from endpoint identity: their credentials are not
interchangeable and are verified by separate stores.

## Transport

- Gateway initiates all connections; control plane has no gateway listener.
- `DEVICE_CONTROL_URL` must be HTTPS outside local development. Wrap with TLS
  and, where feasible, mTLS at the ingress. The gateway credential is a bearer
  secret: never log it, put it in query strings or commit it.
- Control (`/heartbeat`, `/commands`), telemetry (progress) and evidence
  (metadata refs only) are separate paths on the same credential so a future
  WebSocket/gRPC transport can replace HTTP without changing domain objects.
- Queueing is bounded (`DEVICE_GATEWAY_QUEUE_SIZE`, default 32). Admission
  failure returns a bounded `rejected:backpressure` result rather than dropping
  work silently.
- Pull is limited per request (max 50, default 10) and per gateway.

## Command envelope

`GET /v1/gateways/{id}/commands` returns envelopes with:

`command_id`, tenant, endpoint, gateway, `task_ref`, `run_ref`,
`correlation_id`, capability id/version, typed parameters, intent, deadline,
idempotency key, lease, approval, policy version, policy decision, risk tier,
state hash, expected state, attempt and protocol version.

The gateway rejects wrong tenant/gateway, expired deadline, missing
lease/approval for writes, unsupported capability/version, invalid typed
parameters, blocked app/secret field, changed state hash, unsupported protocol
version and conflicting duplicates.

## Results

Gateway results use `received`, `accepted`, `executing`, `succeeded`, `failed`,
`rejected`, `timed_out`, `cancelled`, `uncertain` (see
`contracts/v1/gateway-command-result.schema.json`). Progress is reported
separately and may be skipped; the final result is authoritative.

## Offline and reconnect

- The gateway pulls only while the control plane marks it online/degraded.
- Expired queued commands become `expired`; dispatched work that overruns its
  deadline becomes `timed_out`.
- Duplicate `command_id` delivery is suppressed by a durable gateway ledger.
  A duplicate whose earlier outcome is unknown is reported `uncertain` unless
  the capability declares `supports_idempotency`.
- Late results after a terminal state are retained as audit/outbox records and
  never reopen the command.
- Reconnect: the gateway heartbeats, flushes ledger `result_pending` rows, then
  pulls again. It does not replay uncertain non-idempotent actions.

## Configuration

| Variable | Purpose |
| --- | --- |
| `DEVICE_CONTROL_URL` | control-plane base URL |
| `DEVICE_GATEWAY_ID` | gateway id |
| `DEVICE_GATEWAY_CREDENTIAL` | access credential (≥32 chars) |
| `DEVICE_GATEWAY_DB` | durable ledger path (`/data/gateway-ledger.sqlite3`) |
| `DEVICE_GATEWAY_ADAPTER` | `fake`, `android` or `null` |
| `DEVICE_GATEWAY_ADB_PATH` | operator-configured adb binary |
| `DEVICE_GATEWAY_SERIAL` | operator-configured device serial |
| `DEVICE_GATEWAY_ALLOWED_APPS` | comma-separated package allowlist |
| `DEVICE_GATEWAY_QUEUE_SIZE` | bounded queue capacity |
| `DEVICE_GATEWAY_HEARTBEAT_SECONDS` | heartbeat interval |
| `DEVICE_GATEWAY_POLL_SECONDS` | poll interval |
| `DEVICE_GATEWAY_BATCH_SIZE` | pull/execute batch |

## Tests

`tests/test_gateway_protocol.py` and `gateway/tests/`:

- enrollment replay and credential rotation;
- gateway/endpoint credential separation;
- stale heartbeat → offline + event;
- wrong gateway and wrong-tenant delivery denied;
- bounded queue backpressure;
- gateway revocation invalidates leases, approvals, queued commands and endpoint
  online state;
- pull before first heartbeat returns `409 gateway_not_online`;
- adapter crash/timeout/disconnect isolation.

Real TLS/mTLS termination, production key distribution and multi-process rate
limiting are deployment work and are not claimed as tested here.
