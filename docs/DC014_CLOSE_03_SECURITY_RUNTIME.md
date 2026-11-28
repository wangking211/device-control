# DC-014-CLOSE-03 Security and Runtime Notes

Date: 2026-11-28

## Bandit B110 — WebSocket close (01)

`HomeAssistantWebSocket.close()` is now idempotent and never uses an empty
`except`:

- normal close clears `last_close_error`;
- `ConnectionClosed`/`OSError` (already-closed races) are recorded by class
  name;
- unexpected exceptions are recorded and logged only as the exception class,
  never message/payload/token;
- close failure never raises over the caller's primary shutdown exception.

Tests cover success, repeated close, expected transport error and unexpected
error. Bandit reports **no issues** and pip-audit reports **no known
vulnerabilities** on `requirements/audit.txt`.

## Owner lease expiry and incarnation (02)

`ha_ingest_state.owner_generation` is the fencing token and
`owner_incarnation` is the process epoch. The logical `owner_ref` name is
separate from the incarnation.

- Same owner **and** same incarnation while unexpired → renew, generation stays.
- Same owner after expiry, or a restarted process with a new incarnation →
  new generation (never reuse an expired epoch).
- Different owner with an unexpired lease → `owned_by_other`.
- Renewal rejects expired leases and mismatched owner/incarnation/generation.
- `record_ha_event`/`record_ha_gap` verify owner + incarnation + generation +
  unexpired lease inside the same transaction, so an expiry/commit race cannot
  authorize a stale write.
- The worker generates `uuid4().hex` per process; `HA_OWNER_ID` remains the
  logical label used for metrics.

Tests include same-name restart, same-incarnation expiry, expired renew/write
rejection, old-incarnation fencing, and concurrent takeover yielding exactly
one owner.

## Durable TaskRun projection (04)

`DeviceRunState` is a JSON-compatible value (`schema:
mindos.device-run/v1`) carrying task_ref, run_ref, lease_id, lease_mode,
command_id, idempotency_key, canonical/provider status, reconciliation flag,
verification and Evidence refs. It can be stored in the existing canonical
TaskRun/AgentTask context; it creates no new table or task engine.

The coordinator still releases only for terminal outcomes and retains the lease
for `running`, `verifying`, `queued`, `waiting_approval` and `unknown`.
`unknown` is reconciled by polling the same command/idempotency key, never
resubmitted.

Caller-supplied leases are now checked for tenant, endpoint, task_ref, run_ref,
holder, mode and active state. Acquired responses are validated for lease_id,
endpoint, mode, task/run and tenant; a partially valid response is released
before failing.

## Canonical TaskRun call-site audit (03) — BLOCKED

The canonical execution path is:

```
API route → TaskEntity → create_execution_job() → AgentTask (ExecutionJob)
          → Agent Node (TypeScript) claim → runtime/provider driver
```

`apps/api-gateway/app/task_engine_v1/application/execution_job.py` only
enqueues an AgentTask. The Agent Node provider drivers are TypeScript
(`apps/agent-node-npm/src/drivers/*`) and no driver or Python API route invokes
`DeviceRunCoordinator`. The coordinator is exposed in
`edge-agent/connectors/` with tests, but there is no production call site.

Adding one would require either a new TypeScript device provider in the Agent
Node or a new Task Engine execution path; the first duplicates protocol logic,
the second risks a parallel execution engine. Neither was done without the
live environment and an explicit architecture decision. Therefore C03-05,
C03-12 and C03-13 remain BLOCKED.

## MindOS CI (05)

Local source gates pass; remote runs `46132730981`/`46132731983` job logs are
NOT_FOUND from the connector and no GitHub token is available. No root cause is
guessed. See `artifacts/dc014-close-03/ci-gate-reproduction.md`.
