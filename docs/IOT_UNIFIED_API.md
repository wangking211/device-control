# Unified IoT API (Design)

Physical endpoints are not implemented in DC-011; this is the versioned logical
surface for DC-012, following existing `/v1` naming and tenant-from-token rules.

| Domain | Logical operations | Owner |
| --- | --- | --- |
| Platform instance | create/list/get/disable/rotate credential | Device Control |
| Adapter catalog/lifecycle | install/enable/configure/test/authorize/activate/disable/upgrade/uninstall | Device Control |
| Device | discover/list/get/claim/approve/unpair/group | Device Control |
| Capability | list/get | Device Control registry |
| Command | submit/get/cancel/approve | Device Control |
| Telemetry | query/subscribe cursor | Device Control |
| Event | cursor/subscribe/ack | Device Control |
| Twin | desired/reported/observed read/write-desired | Device Control |
| Evidence | metadata/content link | Device Control |
| Audit | query by device/command/adapter | Device Control |

## Request shape for MindOS

MindOS sends only: canonical `device_id`, `capability_id/version`, typed
parameters, deadline, idempotency key, task/run/correlation refs, and an approval
ref/nonce when required. It never sends platform-native ids, platform admin
tokens, or risk tiers.

## Contract rules

- Tenant from verified identity; no body tenant override.
- Discovery returns `pending`; no execute permission until claim/approval.
- Command submission inherits DC-010 manifest/approval/lease/state rules.
- Telemetry/twin read follows tenant scope; telemetry is not an approval input.
- Events use the existing platform envelope; opaque evidence refs only.
- OpenAPI export and compatibility tests are required before endpoints are
  exposed; no endpoint may exist without a real UI/Agent/CLI consumer.

## Mapping to current API

Existing `/v1/commands`, `/v1/approvals`, `/v1/leases`, `/v1/events`,
`/v1/evidence`, `/v1/gateways` remain the command/evidence surface. New
platform/adapter/device/twin endpoints require a later migration ADR and
consumer tests; DC-011 deliberately does not add tables or endpoints.
