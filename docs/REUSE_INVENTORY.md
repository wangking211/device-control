# Reuse Inventory (DC-011)

| Capability | Existing asset | Reuse decision |
| --- | --- | --- |
| Identity / service tokens | `platform/packages/foundation-auth`; MindOS HS256 claims | Reuse; adapters never receive platform admin tokens |
| Object storage | `platform/packages/foundation-storage` (`ObjectStorage`, local/S3/COS) | Reuse behind `evidence.get_object_store` |
| Event envelope | `platform/contracts/event/event-envelope-0.1.schema.json` (canonical snake_case draft) | Align Device Control adapter events; do not create a third envelope |
| Observability | Device Control `/v1/metrics`, diagnostics, alerts; platform conventions | Extend existing metrics; no new monitor stack |
| Product connector runtime | MindOS provider registry/connector framework | MindOS provider descriptor uses it; no second runtime |
| Command state machine | `device_commands`, `commands.py`, outbox | Extend statuses only by ADR; adapter is not a command engine |
| Evidence | `device_evidence`, object store, hash/proof | Reuse; platform adapter returns opaque refs only |
| Storage/key proof | Ed25519 manifest signing, redaction HMAC proof | Reuse patterns; no new key store |
| Agent runtime | ai-platform Agent Foundation/Runtime | Not used for device execution; adapters are not agents |

## Not reused / intentionally new

- Adapter SPI and lifecycle manager: no existing general plugin runtime with
  device-specific policy/timeout/provenance semantics. It is a thin port, not a
  second runtime; production adapters run in isolated workers.
- Canonical platform/device/native-mapping contracts: Device Control is the
  domain authority and the existing endpoint model does not cover external
  platform instances or native ids.
- MQTT topic/ACL helper: optional transport helper, no broker implementation.

## Rules

- Shared infrastructure is imported, not copied. Where the standalone repo
  cannot import a monorepo package, an adapter/port and an explicit dependency
  are preferred; no silent fallback.
- New tables/endpoints require a real consumer and an ADR; DC-011 is design +
  contracts only, so no device migration is added yet.
