# DC-013 Docker + Live Home Assistant E2E Runbook

Status: configuration delivered; **BLOCKED** in this environment (no Docker
daemon, no HA instance/token). Do not use a production HA config or token.

## Topology

`docker-compose.ha.yml`:

- `home-assistant` (ghcr.io/home-assistant/home-assistant:2026.11.3) with
  `ha-test/config` (demo integration only);
- `device-control` (non-root control plane, `/data` volume, evidence store);
- `ha-adapter` (non-root worker, read-only root, no capabilities, tmpfs);
- isolated compose network; HA port exposed only for local testing.

## Bring up

```bash
export DEVICE_CONTROL_ADMIN_TOKEN=local-dev-token-0123456789
export MINDOS_IDENTITY_HMAC_KEY=local-dev-identity-key-0123456789
export DEVICE_CONTROL_REDACTION_HMAC_KEY=local-dev-redaction-key-0123456789
docker compose -f docker-compose.ha.yml up -d home-assistant device-control
```

Complete HA onboarding with a test-only user and create a long-lived token
(Profile → Security). Export `HA_TOKEN`; never commit it.

## Seed device-control

1. Create a platform instance (returns a one-time `gateway_credential`):

```bash
curl -X POST http://localhost:8085/v1/platform-instances \
  -H "Authorization: Bearer $ADMIN_JWT" -H 'Content-Type: application/json' \
  -d '{"platform_instance_id":"ha-1","adapter_id":"home-assistant",
       "base_url":"http://home-assistant:8123","secret_ref":"vault:ha-test-token",
       "platform_version":"2026.11"}'
```

2. Read HA states and sync only synthetic allowlisted entities:

```bash
curl -H "Authorization: Bearer $HA_TOKEN" http://localhost:8123/api/states
```

Post the discovered device list to
`POST /v1/platform-instances/ha-1/discover`, claim with explicit capability ids
(default claim is read-only), then remove all other entities from the allowlist.

3. Start the worker with `HA_TOKEN`, `HA_ALLOWED_ENTITIES`,
   `DEVICE_GATEWAY_CREDENTIAL` and `DEVICE_GATEWAY_ID=ha-ha-1`.

## Test matrix

- platform discovery → pending; claim default read-only; explicit write grant;
- observe temperature sensor; ingest telemetry/twin; late/duplicate events;
- approval-required light command; denied approval → confirm no HA service call;
- state hash/version mismatch/stale → no service call; invalid entity/capability;
- HA unavailable/auth failure/token revoked; HA restart/reconnect;
- duplicate command idempotency; cancel before/after dispatch;
- tenant bypass attempts; evidence/audit correlation.

Collect logs with tokens redacted. `docker compose down -v` for reset; never
point `HA_BASE_URL` at production or personal HA.
