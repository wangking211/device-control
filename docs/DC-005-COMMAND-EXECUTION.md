# DC-005 — Command Execution State Machine & E2E Loop

Status: **implemented and tested** in-process with the fake Android adapter.
Live MindOS TaskRun correlation and real-device E2E are **BLOCKED** in this
environment.

## Ownership

MindOS remains authoritative for Task/TaskRun, scheduling, business workflow
and user-facing approval UX. Device Control owns `DeviceCommand`, device
session, lease, device policy, dispatch, device result, verification and
evidence references.

Every command carries `task_ref`, `run_ref` and `correlation_id`. No competing
task engine or task table is created; these are references only.

## State machine

```
created → validated → authorized → queued → dispatched → received
        → accepted → executing → verifying → succeeded
```

Terminal alternatives: `rejected`, `failed`, `timed_out`, `cancelled`,
`uncertain`, `expired`.

- Every transition is recorded in `command_transitions` with actor, reason and
  timestamp, and emits an outbox event.
- Terminal states never reopen. Late results are retained in audit/outbox but
  do not change the terminal status.
- `succeeded` requires verification (`method`, `verified=true`, `observed_at`,
  and `adapter_guarantee=true` for `adapter_ack`). Otherwise the result is
  downgraded to `uncertain` with `verification_insufficient`.
- Transport ACK (`received`/`accepted`) is never success.

## Submission checks

Principal and tenant; scope; trusted online endpoint and gateway; supported
capability and version; typed parameters against the capability input schema;
deadline bounds; active lease held by the principal; policy and approval;
state hash/preconditions; idempotency key and payload hash. The command,
initial transitions, audit and outbox rows are persisted atomically before
dispatch.

## Idempotency

Unique scope: `(tenant_ref, endpoint_id, capability_id, idempotency_key)`.

- Same key + same payload → existing command, `deduplicated: true`.
- Same key + different payload → `409 idempotency_conflict`.
- Gateway ledger deduplicates `command_id` and the idempotency key across
  restarts. Conflicting duplicate payloads are rejected.
- Uncertain non-idempotent actions are never retried transparently.

## Cancellation / timeout

- Before dispatch: `created/validated/authorized/queued → cancelled`.
- After dispatch: cancellation is refused with `409 cancel_not_guaranteed`
  because the action may already have happened.
- Queued work past its deadline becomes `expired`.
- Dispatched work past its deadline becomes `timed_out`.
- Late results are retained with `late_result_retained: true`.

## Verification

Capability-defined: adapter ACK (only with documented guarantee), read-after-
write, UI state, screenshot predicate, sensor observation or manual
confirmation. Record method, observed state, timestamp, quality and evidence
refs. Confidence is never fabricated.

## Events

`GET /v1/events` returns the transactional outbox envelope: `event_id`,
`event_type`, `event_version`, `occurred_at`, `tenant_ref`, `source_ref`,
`correlation_id`, optional `task_ref`/`run_ref`, aggregate and payload.
Delivery is at-least-once, ordered per tenant; consumers deduplicate by
`event_id` and acknowledge with `POST /v1/events/ack`.

Event types include gateway/endpoint lifecycle, lease acquired/released/
expired, `command.queued/dispatched/progress/succeeded/failed/uncertain/
expired/timed_out`, `command.late_result`, policy/approval events and
`endpoint.credential_rotated`.

## MindOS integration

See `docs/MINDOS-INTEGRATION.md`. MindOS stores the Device Control command id
on its TaskRun, polls status/events, renders redacted evidence metadata and
never calls ADB or the gateway directly. If Device Control is unavailable,
MindOS must degrade device features only; non-device tasks keep working.

## E2E tested in this repo

`gateway/tests/test_worker_e2e.py` runs the real control plane (FastAPI test
client) with the real gateway worker and fake Android adapter:

- submit → pull → accepted/executing → result → verified `succeeded`;
- adapter crash/timeout → `uncertain`;
- changed screen after approval → `rejected` before the device call;
- user takeover → local pause and rejection;
- disconnect mid-command → `uncertain`;
- duplicate uncertain non-idempotent command not re-executed;
- bounded queue backpressure.

Real Android and live MindOS TaskRun correlation remain blocked; see
`acceptance/ACCEPTANCE-MATRIX.md`.
