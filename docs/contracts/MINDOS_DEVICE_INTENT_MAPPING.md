# MindOS DeviceCommandIntent Mapping (DC-008)

Audited legacy shape (provider-neutral dataclass found in the MindOS workspace):

```
DeviceCommandIntent(command_id, tenant, device_id, capability, operation,
                    parameters, requested_by, approval_ref, idempotency_key,
                    timeout_seconds)
```

MindOS keeps Task/TaskRun. Device Control is the only device command authority.

## Field mapping

| MindOS intent | Device Control command | Notes |
| --- | --- | --- |
| `command_id` | `correlation_id` (and default `idempotency_key`) | external id; response returns a new `command_id` stored as `device_command_ref` on the TaskRun |
| `tenant` | verified token tenant | provider rejects mismatch before HTTP |
| `device_id` | `endpoint_id` | resolved via `endpoint_for_device`; Device Control owns the inventory mapping |
| `capability` | `capability_id` | manifest must declare it |
| `operation` | manifest operation | sent only for audit; control plane/gateway use manifest operation and reject mismatch |
| `parameters` | `input` | validated against manifest input schema |
| `requested_by` | verified principal subject | provider rejects actor spoofing; lease holder must match |
| `approval_ref` | `approval_id` (+ `approval_nonce`) | legacy shape has no nonce; provider must obtain it from the approval response |
| `idempotency_key` | `idempotency_key` | default `command_id`; same key+payload returns existing |
| `timeout_seconds` | `deadline` | now + timeout, bounded by control plane |

Missing from the legacy shape and supplied by MindOS context: `run_ref`,
`task_ref`, observed `state_hash`/`state_version`, endpoint/lease selection.

## Status mapping

`created/validated/authorized/queued → queued`; `dispatched/received/accepted/
executing/verifying → running`; `succeeded → succeeded`; `rejected → rejected`;
`failed/timed_out → failed`; `uncertain → uncertain`; `cancelled/expired →
cancelled`.

MindOS UI must show `uncertain` explicitly and must not auto-retry it. Cancel
before dispatch is authoritative; after dispatch, MindOS shows "cancellation
requested" until the final status.

## Errors and retries

- 401/403/404: do not retry; fix identity/scope/resource.
- 409: idempotency conflict or stale approval; do not retry with a new key.
- 422: fix parameters/state.
- 429: backoff.
- 5xx/transport: retry with the same idempotency key and trace id only.
- `uncertain`: never retry; reconcile manually or through a new approved action.

`examples/mindos_provider.py` implements this mapping and retry policy. A live
MindOS deployment was not available in this environment, so the real API call
and TaskRun E2E remain **BLOCKED**; `examples/mindos_client.py` and the provider
contract tests are the delivered integration surface.
