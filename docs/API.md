# HTTP API (v1)

All `/v1` routes require `Authorization: Bearer <token>` except endpoint
heartbeat (endpoint credential), gateway activation (enrollment token) and the
contract catalog.

Errors use `{"code": "...", "detail": ...}` with the semantics in
`docs/DC-002-SECURITY-AUTH.md`.

## Contracts

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/health/live` | none | liveness |
| GET | `/health/ready` | none | contracts, DB and identity configuration |
| GET | `/v1/contracts` | none | catalog |
| GET | `/v1/contracts/{name}` | none | schema |
| POST | `/v1/contracts/{name}/validate` | none | shape validation |

## Endpoints

| Method | Path | Scope |
| --- | --- | --- |
| POST | `/v1/endpoints` | `device.endpoint.write` |
| GET | `/v1/endpoints` | `device.endpoint.read` |
| GET | `/v1/endpoints/{id}` | `device.endpoint.read` |
| GET | `/v1/endpoints/{id}/capabilities` | `device.endpoint.read` |
| POST | `/v1/endpoints/{id}/heartbeat` | endpoint credential |
| POST | `/v1/endpoints/{id}/credentials/rotate` | `device.endpoint.write` |
| DELETE | `/v1/endpoints/{id}` | `device.endpoint.write` |

## Gateways

| Method | Path | Auth/scope |
| --- | --- | --- |
| POST | `/v1/gateways` | `device.gateway.write` |
| GET | `/v1/gateways` | `device.gateway.read` |
| GET | `/v1/gateways/{id}` | `device.gateway.read` |
| POST | `/v1/gateways/{id}/activate` | enrollment token |
| POST | `/v1/gateways/{id}/heartbeat` | gateway credential |
| POST | `/v1/gateways/{id}/credentials/rotate` | `device.gateway.write` |
| DELETE | `/v1/gateways/{id}` | `device.gateway.write` |
| GET | `/v1/gateways/{id}/commands?limit=` | gateway credential |
| POST | `/v1/gateways/{id}/commands/{cid}/progress` | gateway credential |
| POST | `/v1/gateways/{id}/commands/{cid}/result` | gateway credential |

## Leases, policy, approvals

| Method | Path | Scope |
| --- | --- | --- |
| POST | `/v1/device-leases` | `device.lease.acquire` |
| DELETE | `/v1/device-leases/{id}` | `device.lease.release` |
| POST | `/v1/policy/evaluate` | `device.policy.evaluate` |
| POST | `/v1/approvals` | `device.approval.request` |
| POST | `/v1/approvals/{id}/decision` | `device.approval.decide` |
| POST | `/v1/approvals/{id}/consume` | `device.approval.decide` (legacy/compat) |

`holder_ref`, `requester_ref`, `approver_ref` and `tenant_ref` are derived
from verified claims; body values cannot override them.

## Commands, events, audit

| Method | Path | Scope |
| --- | --- | --- |
| POST | `/v1/commands` | `device.command.submit` |
| GET | `/v1/commands` | `device.command.read` |
| GET | `/v1/commands/{id}` (`?include=transitions`) | `device.command.read` |
| GET | `/v1/commands/{id}/evidence` | `device.command.read` |
| POST | `/v1/commands/{id}/cancel` | `device.command.cancel` |
| GET | `/v1/events` | `device.event.read` |
| POST | `/v1/events/ack` | `device.event.read` |
| GET | `/v1/audit` | `device.audit.read` |
| POST | `/v1/maintenance` | `device.audit.read` + admin |

## Examples

Submit (user/agent token, lease holder = subject):

```json
POST /v1/commands
{
  "endpoint_id": "phone-1",
  "capability_id": "app.launch",
  "capability_version": "1.0.0",
  "input": {"app_id": "com.example.notes"},
  "intent": "Open the notes app",
  "deadline": "2026-11-26T12:00:00+00:00",
  "idempotency_key": "task-1-step-1",
  "lease_id": "lease_...",
  "task_ref": "task-1",
  "run_ref": "run-1",
  "correlation_id": "corr-1"
}
```

Gateway result:

```json
POST /v1/gateways/gateway-a/commands/cmd_.../result
{
  "status": "succeeded",
  "output": {"foreground_app": "com.example.notes"},
  "verification": {
    "method": "ui_state",
    "verified": true,
    "observed_at": "2026-11-26T12:00:03+00:00",
    "quality": "high"
  },
  "evidence_refs": ["sha256:..."]
}
```

Event poll: `GET /v1/events?after_occurred_at=...&after_event_id=...`, then
`POST /v1/events/ack {"event_ids": [...]}`.
