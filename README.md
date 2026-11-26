# Device Control service

This is the standalone source repository for `products/device-control` in ai-platform.

## Scope

The service owns device inventory and trust, device policy and physical-device leases, sessions, action audit/evidence references, and device gateways. Consumer products retain task/run/business approval authority. Shared wire contracts are provider-neutral; hardware drivers stay behind isolated gateway adapters.

## Current milestone: D1 contract service

Implemented: liveness/readiness checks; read-only v1 contract catalog and schema retrieval; JSON Schema validation; container build. Not implemented: authenticated endpoint enrollment, device inventory persistence, command execution, lease/policy engine, event delivery, or hardware drivers. No device action endpoint is exposed in this milestone.

See `docs/CONTRACT_COMPATIBILITY.md` for canonical schema synchronization.
