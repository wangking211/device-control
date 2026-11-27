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

## Storage adapter

Routes use `evidence.get_object_store()`; they never instantiate a backend.
`DEVICE_CONTROL_EVIDENCE_BACKEND` selects:

- `local` (default dev/test): filesystem root `DEVICE_CONTROL_EVIDENCE_DIR`;
- `foundation`/`s3`/`cos`: `ai_platform_foundation_storage.storage_from_env`
  (the existing ai-platform storage package). If the package is not installed
  the service reports storage unavailable instead of silently falling back.

The port exposes put/get/head/list/health/delete. Object keys are immutable
(`<hash-prefix>/<evidence-id>/content.bin`); tenant isolation is enforced by the
API before lookup, never by key guessing.

## Backups and restore

`scripts/backup_sqlite.py` writes a consistent DB copy, evidence tree, counts
and SHA-256 manifest. `scripts/restore_sqlite.py` defaults to a dry run that
checks DB integrity, the backup manifest, every referenced object hash, and
lists missing/corrupt/orphan objects. `--apply` refuses a non-empty target and
copies into an isolated directory. Record RPO/RTO after an actual drill.

## Limitations

- The local object store is not replicated; production must use durable object
  storage with encryption at rest and backup.
- Redaction is performed by the gateway before upload. The control plane
  rejects obviously unredacted screenshot metadata but cannot verify pixel-level
  redaction; gateway tests are the evidence for that property.
