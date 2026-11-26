# DC-002 — Security, Identity, Authorization & Approval Hardening

Status: **implemented and tested** in this repository.

## Principal model

Verified HS256 tokens (claims shape from MindOS
`HmacBearerIdentityProvider` and `ai-platform/platform/packages/foundation-auth`):

| Claim | Meaning |
| --- | --- |
| `sub` | principal subject (user, service id, admin) |
| `tenant` / `extra.tenant_id` | tenant, authoritative |
| `roles` | admin roles map to `*` scopes |
| `permissions` / `extra.capability` / `extra.scopes` | device scopes |
| `iss`, `exp`, `nbf`, `jti` | issuer, expiry, validity, credential id |

`Principal.principal_type` is `user`, `service`, `admin` or `gateway` (gateway
uses an opaque credential, not a platform token). Missing secret/key or
production misconfiguration fails closed with 503 for writes.

## Scope catalogue

`device.endpoint.read|write`, `device.lease.acquire|release`,
`device.policy.evaluate`, `device.approval.request|decide`,
`device.command.submit|read|cancel`, `device.gateway.read|write`,
`device.event.read`, `device.audit.read`, plus `device.safety_critical` for R3.

Wildcards `*` and `device.*` are honoured. Admin roles
(`admin`, `platform_admin`, `device_admin`, `superadmin`) receive `*`.

## Bootstrap token

`DEVICE_CONTROL_ADMIN_TOKEN` is accepted only outside production, requires a
tenant to be named for provisioning, and is rejected in production even when
configured. It cannot approve its own requests (self-approval is denied).

## Tenant isolation

Tenant comes from claims. A body/query `tenant_ref` that differs from the
verified tenant is `403 tenant_scope_mismatch`. Other tenants' resources return
`404 not_found`. Every SQL read/write is tenant-scoped, including commands,
gateways, approvals, events and audit.

## Approval binding

An approval digest binds:

```
tenant, endpoint, device id + fingerprint, gateway, capability id + version,
manifest operation, canonical parameters, intent, requester, lease, policy
version, manifest digest, state hash + version, one-time nonce
```

`POST /v1/approvals/{id}/decision` ignores `approver_ref` from the body; the
approver is the verified principal. Self-approval is `403 self_approval_denied`.

Consumption is atomic (`BEGIN IMMEDIATE`) and revalidates:

- approval still `approved` and unexpired;
- exact binding digest and state hash;
- endpoint online and not revoked;
- lease still active;
- then marks `consumed` and inserts the command/approval audit/outbox rows.

Revocation, lease release/expiry and policy/state changes invalidate pending
approvals and queued work.

## Storage hardening

- Versioned migrations (`src/device_control/schema.py`, versions 1–4) adopt
  legacy tables and preserve rows.
- WAL, `foreign_keys=ON`, busy timeout, unique active-lease and idempotency
  indexes.
- Credentials are stored as SHA-256 digests; only one-time plaintext is
  returned. API responses never include `credential_hash`.
- Payload cap (default 256 KiB) and per-token rate limit (default 240/min).
- Audit records and outbox events are written in the same transaction as the
  mutation.
- The service never logs bodies, credentials or raw screen content.

## Error semantics

401 unauthenticated; 403 insufficient scope/tenant/policy/self-approval; 404
tenant-hidden resource; 409 conflict/stale/illegal transition/idempotency;
422 validation; 429 rate limited; 503 identity dependency unavailable.

## Tests

`tests/test_security.py`, `tests/test_contract_api.py`:

- forged approver field ignored; bad signature rejected;
- cross-tenant reads/decisions return 404;
- released/expired lease blocks consumption;
- endpoint/gateway revocation invalidates approvals and queued commands;
- parameter/version/state-hash tampering returns `approval_binding_mismatch`;
- concurrent consumption yields exactly one 201 and one 409;
- production rejects the bootstrap token;
- missing identity provider returns 503 and readiness fails;
- secrets absent from responses/logs;
- legacy migration preserves endpoint/lease/approval rows;
- payload limit returns 413; expired/issuer-mismatch tokens return 401.

Docker non-root volume write is configured but **BLOCKED** in this environment
(no Docker). See `acceptance/ACCEPTANCE-MATRIX.md`.
