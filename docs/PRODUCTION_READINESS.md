# Production Readiness (DC-009)

Status: configuration, scripts and runbooks are delivered. Docker persistence,
TLS/mTLS and real-device rows are **BLOCKED** in this environment (no Docker
daemon, no adb/device, no live MindOS).

## Topology

```
Internet/private ingress (TLS, optional mTLS)
  ├── device-control control plane (non-root, /data volume: SQLite + evidence)
  └── object storage (evidence bytes; local FS adapter for dev only)

Gateway host / edge box
  └── device_gateway (outbound HTTPS/mTLS, no inbound port)
        └── USB or paired Wi-Fi ADB → one Android device (first supported topology)
```

One gateway = one Android device. Future multi-device support requires an
Adapter Manager; it is not claimed here.

## Transport and credentials

- Set `DEVICE_CONTROL_REQUIRE_HTTPS=true` in production; non-loopback plain HTTP
  is rejected (`426 https_required`). Terminate TLS/mTLS at the ingress and pass
  `X-Forwarded-Proto: https`.
- Gateway credential is a bearer secret over TLS; prefer mTLS for the gateway
  identity. Never put secrets in URLs, command lines, images or logs.
- Enrollment token: one-time, short-lived, revoked at activation.
- Gateway/endpoint credentials: rotate and revoke through the API; revocation
  invalidates leases, approvals and pending work.
- Manifest signing: set `DEVICE_CONTROL_MANIFEST_HMAC_KEY` and
  `DEVICE_GATEWAY_MANIFEST_HMAC_KEY` (≥32 bytes). Production control plane
  rejects unsigned manifests when the key is configured and fails closed if it
  is not configured.

## Installation / upgrade

```bash
python scripts/gateway_preflight.py --json          # network, adb, disk, manifest
python scripts/verify_upgrade.py --package ... --signature ... --public-key ...
# human approval record required before replacing the gateway
```

The gateway image installs `adb`; USB passthrough to a container is a host
security decision (prefer a dedicated edge host). Upgrades that fail signature
verification must be rejected.

## Backup and restore

```bash
python scripts/backup_sqlite.py \
  --db /data/device-control.sqlite3 --out /backup/20261126 \
  --evidence /data/evidence
```

The tool uses SQLite's online backup API, runs `integrity_check`, copies
evidence, and writes SHA-256/count manifests. Restore drill: stop writers,
restore DB + evidence, start the control plane, verify `GET /health/ready`,
reconnect the gateway (reconcile, no replay of uncertain non-idempotent work),
and verify evidence hashes. Record RPO/RTO in the acceptance matrix.

## Monitoring / alerts

- `GET /health/live`, `/health/ready`.
- `GET /v1/metrics` (admin) counters.
- `GET /v1/gateways/{id}/diagnostics`: heartbeat age, queue depth/age, manifest
  digests, last error, health, adapter inventory.
- `GET /v1/alerts`: gateway offline/degraded/stale heartbeat, uncertain command
  count (24h). Wire to the platform alert sink; do not put tenant/subject in
  metric labels.

## Device management

`/admin` is a static operator shell (token stays in memory) that lists gateways,
endpoints and alerts. All data calls re-authenticate and re-authorize on the
backend. Revoke/re-pair/rotate remain API operations; the shell never caches or
stores the token.

## Backup of secrets

Identity keys, manifest keys, TLS keys and gateway credentials are **not** in
the SQLite backup. Use the deployment secret facility and a separate key
recovery procedure.

## Production checklist

- [ ] `DEVICE_CONTROL_ENV=production`, HTTPS enforced, TLS/mTLS verified.
- [ ] Identity issuer/key and manifest key provisioned; no bootstrap token.
- [ ] `/data` volume writable by UID 10001; backup/restore drill done.
- [ ] Evidence object storage durable, encrypted, retention configured.
- [ ] Gateway preflight passes; manifest registered/signed; digest stable.
- [ ] Alerts wired; heartbeat/stale/uncertain/evidence failure reviewed.
- [ ] Upgrade signature + human approval record.
- [ ] Real-device Gate B and live MindOS Gate C evidence recorded.
- [ ] Tenant isolation and revocation tests pass on the deployed build.

Docker build/run, volume persistence and read-only/disk-full behavior were not
executed here; they must remain BLOCKED until run in a Docker-capable
environment.
