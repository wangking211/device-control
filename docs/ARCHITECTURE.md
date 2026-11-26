# Architecture

## Processes

```
MindOS / operator / trusted service
        │  platform HS256 bearer (user, service or admin)
        ▼
┌───────────────────────────────────────────────┐
│ Device Control control plane (FastAPI)        │
│ identity · tenant · endpoints · gateways      │
│ leases · policy · approvals · commands        │
│ outbox/audit · evidence metadata              │
└───────────────▲───────────────────────────────┘
                │ outbound HTTPS, gateway credential
┌───────────────┴───────────────────────────────┐
│ Gateway process (separate deployment)         │
│ heartbeat · bounded queue · dedupe ledger     │
│ execution-side policy revalidation            │
│ adapter SDK ── fake / Android ADB             │
└───────────────┬───────────────────────────────┘
                │ adb argument arrays (never shell)
             Android device
```

There is no `adb`, driver or shell execution inside the control plane. The
gateway makes only outbound requests and does not listen on a public port.

## Trust boundaries

1. **Control plane** trusts only verified platform tokens. Tenant, requester,
   lease holder and approver are derived from claims, never from JSON bodies.
   The local bootstrap token is a provisioning credential and is rejected in
   production.
2. **Gateway** trusts the control plane over the authenticated channel, but
   revalidates binding, deadline, capability, typed parameters, risk, secret
   fields, allowlist and screen/state hash before executing. Local pause never
   needs a cloud round-trip.
3. **Adapter** is the only component allowed to touch hardware. A crash,
   timeout or disconnect becomes `failed`/`uncertain`, never a control-plane
   crash.
4. **MindOS** owns Task/TaskRun and approval UX. Device Control stores only
   `task_ref` / `run_ref` / `correlation_id`; it does not create a competing
   task engine.

## Authorization pipeline

```
verified principal
  → scope check
  → tenant derivation (body mismatches are 403; other tenants are 404)
  → endpoint/gateway online + capability/version
  → active lease (holder bound to principal)
  → policy allow/ask/deny (deny final)
  → approval bound to tenant/endpoint/gateway/capability/version/parameters/
    intent/requester/lease/policy version/state hash
  → single-use consumption + command insert + transitions + audit + outbox
    in one BEGIN IMMEDIATE transaction
```

`allow` is preflight only. `deny` is final. `ask` cannot proceed without a
consumed approval. Approval consumption revalidates endpoint status and lease
in the same transaction as command authorization, so revocation and expiry
cannot race a valid-looking approval.

## Command lifecycle

`created → validated → authorized → queued → dispatched → received → accepted
→ executing → verifying → succeeded`

Terminal alternatives: `rejected`, `failed`, `timed_out`, `cancelled`,
`uncertain`, `expired`. Terminal states never reopen. `succeeded` requires
verification evidence (or a documented adapter guarantee for `adapter_ack`).
Transport acknowledgement is not success.

## Persistence and events

SQLite with WAL, foreign keys and recorded migrations (`schema_migrations`,
versions 1–4). Migrations adopt databases created by the previous lazy schema
without losing endpoints, leases or approvals.

Mutating operations write `command_transitions` plus an outbox row in the same
transaction. `GET /v1/events` exposes at-least-once delivery ordered per tenant;
consumers deduplicate by `event_id` and ack with `POST /v1/events/ack`.
Retention is bounded by `DEVICE_CONTROL_EVENT_RETENTION_SECONDS` (published
events only).

## Failure semantics

| Failure | Result |
| --- | --- |
| Missing/invalid identity | 401 |
| Insufficient scope / tenant mismatch / policy deny / self-approval | 403 |
| Other tenant's resource | 404 (indistinguishable from missing) |
| Busy device, stale approval, illegal transition, idempotency conflict | 409 |
| Schema/typed-parameter failure | 422 |
| Rate limit | 429 |
| Identity dependency unavailable / not ready | 503 (writes fail closed) |
| Adapter timeout/crash/disconnect | command `uncertain` (never blind retry) |

## Extension points

- `DeviceAdapter` port with two implementations: deterministic fake (tests,
  emulator CI) and Android ADB. A new device family adds an adapter, not a new
  runtime or queue.
- `Transport` port for the gateway client so HTTP can later be replaced by
  WebSocket/gRPC without changing domain objects.
- Contract schemas under `contracts/v1` mirror
  `ai-platform/platform/contracts/device`.
