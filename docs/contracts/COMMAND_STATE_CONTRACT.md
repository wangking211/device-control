# Device Command State Contract (DC-014)

`contract_version`: `dc-command-state/v1`

This contract is the single cross-repo status projection. Device Control owns
the authoritative status machine; MindOS stores the projection as a read model
and never writes Device Control state from it. There is no second command state
machine or command database.

## Fields

| Field | Meaning |
|---|---|
| `command_id` | Authoritative Device Control command id |
| `tenant_id` | Tenant that owns the command (Device Control `tenant_ref`) |
| `device_id` / `endpoint_id` / `platform_instance_id` | Bound target identity |
| `task_ref` / `run_ref` | MindOS Task/TaskRun references |
| `correlation_id` / `idempotency_key` | Tracing and retry identity |
| `provider_status` | Raw Device Control/adapter status; always preserved |
| `canonical_status` | The only status consumers may branch on |
| `status_reason` | Machine-readable reason for the current status |
| `verification` | Post-condition evidence supplied by the adapter |
| `evidence_refs` | References only; Evidence blobs stay in the Evidence store |
| `created_at` / `updated_at` / `completed_at` | Lifecycle timestamps |

## Canonical mapping

| Raw status | Canonical |
|---|---|
| `created`, `validated`, `authorized`, `queued` | `queued` |
| `waiting_approval`, `approval_required` | `waiting_approval` |
| `dispatched`, `received`, `accepted`, `executing`, `verifying` | `running` |
| `executed_unverified` | `verifying` |
| `succeeded` | `succeeded` |
| `rejected`, `failed`, `timed_out` | `failed` |
| `uncertain` | `unknown` |
| `cancelled` | `cancelled` |
| `expired` | `expired` |
| anything else / missing / non-string | `unknown` |

`timed_out` projects to `failed` because it is an execution timeout, not proof
that the physical action happened. `uncertain` / `unknown` covers "may have
happened and cannot be verified"; it must not be replayed automatically.

## Invariants

1. `succeeded` requires a verified post-condition. A transport acknowledgement
   (`received`/`accepted`/`executing`) is never success.
2. `executed_unverified` projects to `verifying`, never `succeeded`. The raw
   value is retained in `provider_status`.
3. `uncertain` projects to `unknown` and is never automatically retried; it is
   reconciled first.
4. Unknown provider status projects to `unknown`; no guessing.
5. Terminal status changes require an authoritative Device Control transition
   plus an audit record. Consumers cannot overwrite them.
6. Cancellation is not a physical rollback. A cancel after execution reports
   `too_late`/`cancel_not_guaranteed`; it never claims the device was restored.
7. Retries reuse the same `idempotency_key`. Different payloads with the same
   key are rejected by the control plane.
8. Evidence reads are re-authorized against the tenant/command; the projection
   only carries references.

## Compatibility

The projection is additive: existing `status` fields and Device Control
transitions remain unchanged. Consumers should migrate to `canonical_status`
while continuing to log `provider_status` and `status_reason`. Version changes
must be announced in this document and covered by cross-repo contract tests.
