# Device Control service

This is the standalone source repository for `products/device-control` in ai-platform.

## Scope

The service owns device inventory and trust, device policy and physical-device leases, sessions, action audit/evidence references, and device gateways. Consumer products retain task/run/business approval authority. Shared wire contracts are provider-neutral; hardware drivers stay behind isolated gateway adapters.

## Current milestone: D1 contract service

Implemented: liveness/readiness checks; read-only v1 contract catalog and schema retrieval; JSON Schema validation; container build. Not implemented: authenticated endpoint enrollment, device inventory persistence, command execution, lease/policy engine, event delivery, or hardware drivers. No device action endpoint is exposed in this milestone.

See `docs/CONTRACT_COMPATIBILITY.md` for canonical schema synchronization.

## Endpoint enrollment (D1.1)

Set `DEVICE_CONTROL_ADMIN_TOKEN` to a high-entropy secret before enabling endpoint administration. `POST /v1/endpoints` requires that bearer token, binds the endpoint to a tenant, and returns a one-time endpoint credential; only its SHA-256 digest is stored. Endpoints authenticate heartbeats with that credential. `DELETE /v1/endpoints/{endpoint_id}` revokes the credential immediately. `GET /v1/endpoints?tenant_ref=...` is admin-token protected. The admin token is currently a single deployment-wide bootstrap credential; replace it with the platform service identity before multi-tenant production use. Protect the service with TLS and private network policy.

The API accepts only endpoint enrollment, inventory readback, heartbeat, and revocation. It does not execute device actions or treat reported capabilities as authorization. Reported capabilities are untrusted observations; action execution must add per-tenant policy, pairing approval, and device-scoped leases first.

## Device leases (foundation only)

The admin API can acquire one exclusive lease per online endpoint with `POST /v1/device-leases`; leases bind tenant, task/run references, holder and `read_only` or `control` mode, and expire after 1–3600 seconds. Conflicts return `409 device_busy` with the current holder/task references. Release is tenant-scoped through `DELETE /v1/device-leases/{lease_id}?tenant_ref=...`; expired leases are reclaimed on the next acquisition, and endpoint revocation releases active leases. This is a concurrency primitive, not a complete authorization policy: the deployment-wide admin token still authorizes these calls, and device actions remain unavailable until approval/policy enforcement is added.
