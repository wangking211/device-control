# Contract compatibility

The canonical shared schemas for this repository are maintained in
`ai-platform/platform/contracts/device/`. This standalone repository vendors the
same v1 files under `contracts/v1/` so a checkout remains buildable without a
monorepo path dependency.

## v1 files

| File | Purpose |
| --- | --- |
| `device-endpoint.schema.json` | endpoint + capability snapshot |
| `endpoint-enrollment.schema.json` | endpoint enrollment (now with `gateway_id`) |
| `endpoint-heartbeat.schema.json` | endpoint heartbeat |
| `endpoint-receipt.schema.json` | one-time endpoint credential receipt |
| `device-invocation.schema.json` | provider-neutral invocation envelope |
| `device-result.schema.json` | provider-neutral result envelope |
| `gateway-enrollment.schema.json` | gateway registration |
| `gateway-activation.schema.json` | enrollment-token exchange |
| `gateway-receipt.schema.json` | one-time gateway credential receipt |
| `gateway-heartbeat.schema.json` | gateway liveness/inventory |
| `device-command.schema.json` | control-plane command submission |
| `gateway-command.schema.json` | bounded gateway command envelope |
| `gateway-command-result.schema.json` | execution result/verification |
| `device-event.schema.json` | transactional outbox envelope |
| `device-manifest.schema.json` | trusted capability/risk/verification manifest |
| `adapter-plugin-manifest.schema.json` | adapter provenance/SBOM/resource limits |
| `canonical-device.schema.json` | canonical platform/device/native mapping |
| `device-telemetry.schema.json` | telemetry point |
| `device-twin.schema.json` | desired/reported/observed twin |

## Rules

- `contract_version: v1` is the wire major. Additive optional fields are
  compatible; removing required fields or changing enums requires a new major
  path.
- Contract changes must be applied to **both** repositories in one compatibility
  review. The standalone copy is not a second source of truth.
- Schemas describe transport shape only. Authorization is never inferred from
  them; identity, tenant, scope and policy are enforced by the service.
- The gateway validates its own manifest input schemas in addition to the
  control-plane envelope. A capability that is not in the gateway manifest is
  rejected even if an endpoint once reported it.
