# Evidence Store

Binary evidence is stored in an object store; SQLite keeps only metadata,
hashes and authorization. The local filesystem adapter is for single-host/dev;
a production deployment implements the same `ObjectStore` port against the
platform object store.

## Metadata

`device_evidence` records: `evidence_id`, tenant, gateway, endpoint, device,
command/task/run/correlation refs, type, MIME, SHA-256, size, captured time,
redaction status, retention, storage ref, access policy and deletion time.

## Upload

`POST /v1/gateways/{id}/commands/{cid}/evidence` with a gateway credential and
raw body. Required headers:

- `Content-Type`: `image/png`, `application/json` or `text/plain`;
- `X-Evidence-Type`: `screenshot`, `node_summary` or `artifact_log`;
- `X-Content-SHA256`: hash of the exact bytes;
- `X-Redaction-Status`: `redacted`, `restricted` or `not_required`;
- optional retention seconds and captured-at.

Screenshots/node summaries must be redacted or restricted. Hash mismatch, bad
type/MIME, oversized body, wrong command/gateway or cross-tenant access is
rejected. The service writes the object first and deletes it if metadata
insertion fails.

## Access

- `GET /v1/commands/{id}/evidence` lists metadata (tenant + command scope).
- `GET /v1/evidence/{id}` returns metadata.
- `GET /v1/evidence/{id}/content` streams bytes only after tenant/scope checks,
  re-verifies the hash, sets `Cache-Control: private, no-store`, and writes an
  `evidence.access` audit record.
- `DELETE /v1/evidence/{id}` requires `device.evidence.delete`; it marks the
  record deleted and removes the object.

## Retention

Default 7 days (`DEVICE_CONTROL_EVIDENCE_RETENTION_SECONDS`), bounded 1h–90d.
`POST /v1/maintenance` removes expired objects and keeps an audit record
(`evidence.retention_delete`). Backups copy evidence objects and include hashes
in `backup-manifest.json`.

## Limitations

- The local object store is not replicated; production must use durable object
  storage with encryption at rest and backup.
- Redaction is performed by the gateway before upload. The control plane
  rejects obviously unredacted screenshot metadata but cannot verify pixel-level
  redaction; gateway tests are the evidence for that property.
