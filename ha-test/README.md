# Home Assistant test instance (demo integration only)

This directory is mounted at `/config` in `docker-compose.ha.yml`. It uses the
Home Assistant `demo` integration to create synthetic lights/sensors. Do not
mount a production HA config or token here.

```yaml
default_config:
demo:
http:
  server_port: 8123
logger:
  default: warning
```

To create a test long-lived token:

1. Start `docker compose -f docker-compose.ha.yml up -d home-assistant`.
2. Open `http://localhost:8123`, complete onboarding with a test-only user.
3. Profile → Security → Long-lived access tokens → create a token for the test
   user. Export it as `HA_TOKEN`; never commit it.
4. Create the Device Control platform instance and claim the demo entities using
   the API flow in `docs/DC013_DOCKER_HA_E2E.md`.
5. Set `DEVICE_GATEWAY_CREDENTIAL` from the platform creation response and start
   the `ha-adapter` profile.

The demo integration and exact entity ids are HA-version dependent; verify with
`GET /api/states` and use only allowlisted synthetic entities.
