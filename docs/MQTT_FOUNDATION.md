# MQTT Foundation (Optional)

No MQTT implementation is added in DC-011. `device_control.iot.mqtt_topics`
defines the namespace/ACL helper for a later adapter or broker policy.

## Namespace

`dc/{tenant}/{device}/{endpoint}/{channel}[/{metric}]`

Channels: `telemetry`, `state`, `event`, `command`. Tenant/device/endpoint/metric
segments are validated; no wildcard, `#`/`+`, `.`/`..` or empty segments are
accepted.

## Security

- TLS only in production; client cert or scoped token identity.
- Per-tenant ACL; no cross-tenant wildcard subscription. A client may subscribe
  only its tenant/device/endpoint/channel set.
- `command` topics must be non-retained; a reconnect must not execute an old
  retained command.
- Telemetry/state retained messages require explicit policy and expiry.
- Payload limit, rate limit, duplicate/replay handling, out-of-order sequence and
  dead-letter are adapter/broker policies; telemetry never authorizes a write.

## Message shape

Telemetry uses `device-telemetry.v1`; events use the platform event envelope
with adapter correlation; commands are delivered only by Device Control and
carry `command_id`, idempotency key, deadline, manifest/policy context.

## Decision

Mosquitto/MQTT stays optional until a PoC proves ACL/TLS/replay/backpressure on
a real broker. It is not required for the Home Assistant REST/WebSocket pilot.
