# MindOS integration

MindOS owns Task/TaskRun, scheduling, business workflow and user-facing approval
UX. Device Control owns the device command and its evidence. MindOS never calls
ADB or the gateway directly.

## Identity and scopes

MindOS issues the same HS256 bearer tokens it already uses
(`MINDOS_IDENTITY_HMAC_KEY`, `sub`, `tenant`, `roles`, `permissions`, `iss`).
Grant the device scopes the workflow needs:

- assistant/agent: `device.endpoint.read`, `device.lease.acquire`,
  `device.policy.evaluate`, `device.approval.request`, `device.command.submit`,
  `device.command.read`, `device.command.cancel`, `device.event.read`;
- human approver: `device.approval.decide`;
- operator/admin: `device.gateway.write`, `device.endpoint.write`,
  `device.audit.read`.

For cross-product service tokens, Device Control also accepts the Foundation
Auth service-token shape (`extra.actor.actor_type=service`, `extra.tenant_id`,
`extra.capability`, `extra.resource`). Set
`DEVICE_CONTROL_IDENTITY_AUDIENCE` to this service's audience to pin service
tokens, and keep `actor.service_id == sub`. A service token scoped to
`resource.type=device_endpoint` may only act on that endpoint.

## TaskRun flow

1. Agent creates the MindOS Task/TaskRun as usual.
2. MindOS acquires a device lease:
   `POST /v1/device-leases` with `task_ref`, `run_ref`, `mode`, `ttl_seconds`.
   The holder is the authenticated principal; it cannot be spoofed in the body.
3. MindOS evaluates policy (`POST /v1/policy/evaluate`) to decide whether to
   show an approval prompt. `deny` is final; `ask` needs human approval.
4. For `ask`, MindOS requests an approval bound to the exact capability,
   version, parameters, intent, lease, policy version and observed state hash,
   then a verified human decides it.
5. MindOS submits `POST /v1/commands` with `task_ref`, `run_ref`,
   `correlation_id`, the lease and approval. Store the returned `command_id`
   on the TaskRun as `device_command_ref`.
6. MindOS polls `GET /v1/commands/{id}` or consumes `GET /v1/events`
   (dedupe by `event_id`, ack after processing) and renders status plus
   redacted evidence metadata from `GET /v1/commands/{id}/evidence`.
7. On TaskRun cancellation before dispatch, call `POST /v1/commands/{id}/cancel`.
   After dispatch MindOS must show "cancellation not guaranteed" and reconcile
   the final status.

## Status mapping

| Device Control | MindOS presentation |
| --- | --- |
| `queued`/`dispatched` | pending / dispatched to device |
| `received`/`accepted`/`executing` | in progress |
| `verifying` | verifying outcome |
| `succeeded` | completed with evidence |
| `rejected` | blocked (policy/state/adapter) |
| `failed` | failed (retry only if idempotent and explicitly safe) |
| `timed_out` | timed out; outcome may be unknown |
| `uncertain` | **manual verification required; never auto-retry** |
| `cancelled`/`expired` | not executed |

## Failure isolation

- If Device Control is unavailable, MindOS must degrade device features only.
  Non-device tasks, approvals and scheduling keep working.
- Use a short timeout and circuit breaker; do not retry non-idempotent command
  submissions with a new idempotency key. Reuse the original key to recover the
  existing command.
- Late results after a terminal state are retained by Device Control; MindOS
  should show them as reconciliation notes, not reopen the TaskRun.
- Never copy raw screenshots into MindOS; store only evidence references and
  apply MindOS retention policy.

## Example

See `examples/mindos_client.py` for a dependency-free client that submits a
command, polls to a terminal state and fetches evidence metadata.
