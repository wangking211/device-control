# Operations

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `DEVICE_CONTROL_ENV` | `local` | `local`, `test`, `production`; production rejects bootstrap |
| `DEVICE_CONTROL_DB` | `./var/...` / `/data/...` in prod | SQLite path |
| `DEVICE_CONTROL_ADMIN_TOKEN` | empty | local provisioning only |
| `MINDOS_IDENTITY_HMAC_KEY` | empty | ≥32 bytes; required in production |
| `MINDOS_IDENTITY_ISSUER` | empty | optional issuer pin |
| `DEVICE_CONTROL_IDENTITY_AUDIENCE` | empty | optional audience pin for service tokens |
| `DEVICE_CONTROL_APPROVAL_TTL_SECONDS` | 300 | 30–3600 |
| `DEVICE_CONTROL_ENROLLMENT_TTL_SECONDS` | 300 | 30–900 |
| `DEVICE_CONTROL_GATEWAY_CREDENTIAL_TTL_SECONDS` | 86400 | 300–604800 |
| `DEVICE_CONTROL_ENDPOINT_CREDENTIAL_TTL_SECONDS` | 2592000 | 300–31536000 |
| `DEVICE_CONTROL_COMMAND_MAX_TTL_SECONDS` | 3600 | 5–86400 |
| `DEVICE_CONTROL_STALE_AFTER_SECONDS` | 90 | heartbeat staleness |
| `DEVICE_CONTROL_MAX_REQUEST_BYTES` | 262144 | payload cap |
| `DEVICE_CONTROL_RATE_LIMIT_PER_MINUTE` | 240 | per token/client |
| `DEVICE_CONTROL_EVENT_RETENTION_SECONDS` | 604800 | published events only |
| `DEVICE_CONTROL_EVIDENCE_DIR` | `/data/evidence` | object store root |
| `DEVICE_CONTROL_EVIDENCE_MAX_BYTES` | 8 MiB | upload cap |
| `DEVICE_CONTROL_EVIDENCE_RETENTION_SECONDS` | 604800 | default retention |
| `DEVICE_CONTROL_REQUIRE_HTTPS` | true in production | enforce TLS/forwarded proto |
| `DEVICE_CONTROL_MANIFEST_HMAC_KEY` | empty | require signed manifests |

Secrets belong in a secret manager or deployment secret facility. Never commit
them, put them in query strings, or log them.

## Database and migrations

- Migrations are ordered and recorded in `schema_migrations` (versions 1–4).
  They run on first connection/startup and adopt legacy tables created by the
  pre-DC-002 lazy schema without deleting rows.
- WAL mode, foreign keys and `busy_timeout=5000` are set per connection.
- Production container path is `/data/device-control.sqlite3`, owned by UID
  10001, mounted as a persistent volume. The image starts as non-root.
- Backup: use SQLite's online backup API or stop the service and copy the DB
  plus WAL/SHM files. Test restore into a scratch path before relying on it.
- Schema changes must ship a new migration version and a preservation test
  (see `test_versioned_migration_preserves_legacy_records`).

## Docker

```bash
docker build -t device-control .
docker run -d --name device-control -p 8085:8085 \
  -e DEVICE_CONTROL_ENV=production \
  -e MINDOS_IDENTITY_HMAC_KEY=... \
  -v device-control-data:/data \
  device-control
```

Compose profile for a local gateway: `docker compose --profile gateway up`
(the gateway requires a credential from `scripts/bootstrap_gateway.py`).

## Credential lifecycle

- Endpoint credential: returned once, stored as SHA-256; rotate with
  `POST /v1/endpoints/{id}/credentials/rotate`, revoke with `DELETE`.
- Gateway enrollment token: one-time, short-lived, revoked at activation.
- Gateway access credential: rotate with
  `POST /v1/gateways/{id}/credentials/rotate`; revocation invalidates leases,
  approvals and pending commands.
- Production key rotation for platform identity is owned by the identity
  provider; Device Control pins issuer/secret via environment.

## Maintenance

`POST /v1/maintenance` (admin) expires leases, pending approvals, overdue
queued/dispatched commands, marks stale gateways offline and prunes published
events. It is also invoked opportunistically on command submit and gateway pull.
Run it on a 1-minute schedule for timely stale detection and retention.

## Observability

- `GET /health/live`, `GET /health/ready`.
- `GET /v1/metrics` (admin): process counters for HTTP total/5xx, auth failures,
  identity unavailability, command submissions, dispatches and results by
  terminal status.
- `GET /v1/audit` (tenant-scoped) and `GET /v1/events` provide durable audit and
  outbox slices.
- Never add credential, tenant or subject values as metric labels.

## Incident response

1. Revoke the endpoint and/or gateway; pending approvals and queued commands
   are invalidated in the same transaction.
2. Rotate the affected credentials.
3. Inspect `/v1/audit?resource_id=...` and `/v1/events` for the affected
   aggregate.
4. If an action may have occurred without verification, keep the command
   `uncertain`; do not retry it blindly. Reconcile device state manually.
5. If the identity secret may be compromised, rotate it at the identity
   provider and redeploy; all old tokens fail signature verification.

## Known limitations

- SQLite is single-writer; for multi-instance control planes move to a shared
  database behind the same repository contract (not implemented).
- Rate limiting is process-local.
- TLS/mTLS and secret distribution are deployment responsibilities.
- No real Android device or Docker acceptance has been run in this environment;
  see `acceptance/ACCEPTANCE-MATRIX.md`.
