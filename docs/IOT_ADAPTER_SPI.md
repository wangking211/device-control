# IoT Adapter SPI and Plugin Governance

## SPI

`device_control.iot.spi.AdapterPlugin` (API version 1.0):

- `validate_config(config) -> errors`
- `connect(config, resolve_secret)`, `disconnect()`, `health()`
- `discover(cursor, filters) -> DiscoveryPage`
- `get_device(native_id)`, `get_capabilities(native_id)`
- `observe(native_id) -> Observation`
- `execute(command) -> ExecutionResult`
- `subscribe(event_types, cursor)`, `get_telemetry(native_id, cursor, limit)`
- `reconcile(mapping_state)`

Platform-neutral value objects live in the same module. `ExecutionResult`
separates `accepted`, `executed` and `verified`; `Observation` carries
`observed_at`, quality and state hash.

## Manifest

`contracts/v1/adapter-plugin-manifest.schema.json` requires adapter id/version/
api_version, configuration schema, supported features, permissions, capability
mappings, resource limits and license. It also declares platform versions,
protocols, credential secret refs, schema versions, health checks, SBOM and an
Ed25519 signature. Secrets are `secret_ref` only; literal credentials fail
validation.

## Lifecycle

`installed → enabled → configured → authorized → active → disabled`, with
`failed` on validation/runtime failure and uninstall removing the runtime.
`AdapterLifecycleManager` enforces a call timeout, isolates plugin exceptions,
and opens a circuit after repeated failures. Production must additionally run
the adapter in a separate process with CPU/memory/network/file limits.

## Rules

- Core imports no platform SDK; adapters are loaded through explicit
  registration/packaging, never dynamic import from user input.
- Discovery is untrusted (`trusted=False`); only Device Control claim/activation
  grants capability authority.
- Unknown capability/operation/risk is rejected; risk is registry/manifest
  derived, not agent/platform supplied.
- Platform credentials are resolved server-side and never included in manifests,
  logs, telemetry or UI.
- A revoked adapter/platform instance invalidates leases, approvals and pending
  commands; audit/evidence remain for retention.
- Adapter `accepted` is not success; postcondition read-back is required.
