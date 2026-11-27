# Open Source IoT Platform Research (verified 2026-11-27)

Sources are official project/vendor pages or repositories. Versions are the
latest found on the verification date. Items marked TBD were not verified and
must not be inferred.

## Summary

| Platform | Version | License | Role for Device Control |
| --- | --- | --- | --- |
| Home Assistant | 2026.11.3 (2026-11-23) | Apache-2.0 | First pilot platform (home/office) |
| ThingsBoard | 4.4.1 (2026-11-24), LTS 4.3 | BUSL-1.1 from 4.4; CE 4.3 Apache-2.0 | Enterprise IoT candidate, license review mandatory |
| EdgeX Foundry | 4.0.2 "Palau" (2026-05-29) | Apache-2.0 | Industrial edge framework candidate |
| Eclipse Mosquitto | 2.1.4 (2026-11-17) | EPL-2.0 / EDL-1.0 | Optional MQTT broker/transport, not required |
| ESPHome | 2026.11.0 | Mixed MIT (Python/tooling) + GPLv3 (C++ runtime) | Device firmware, not a platform; adapter/endpoint candidate |

## Home Assistant

- Official docs: https://www.home-assistant.io/, developer docs
  https://developers.home-assistant.io/, REST API
  https://developers.home-assistant.io/docs/api/rest/ (redirects to current
  contributors docs), license https://www.home-assistant.io/developers/license/
- Version: 2026.11.3, published 2026-11-23 (PyPI/GitHub release 2026.11.0 on
  2026-11-04, patch 2026.11.3).
- License: Apache-2.0.
- Runtime: Python package, default HTTP port 8123 (80 under Supervisor).
- API: REST under `/api/`; `GET /api/`, `/api/config`, `/api/states`,
  `/api/states/<entity_id>`, `GET /api/services`, `POST
  /api/services/<domain>/<service>`; SSE `/api/stream`; WebSocket
  `/api/websocket` for long-lived subscriptions (preferred for events).
- Auth: `Authorization: Bearer <access token>`; long-lived tokens created by a
  user; admin-only endpoints exist. A token is a secret and must be referenced by
  secret_ref, never stored in a manifest or log.
- Mapping: HA Device/Entity/Area/Service/State → Device Control
  Device/Endpoint/Capability/Property/Twin; entity discovery is pending until
  claim.
- Offline: HA local automation continues if the cloud/Device Control is down;
  Device Control must not assume commands execute; reconnect requires state
  reconcile.
- Limitations: entity domains/attributes vary by integration; WebSocket event
  payloads are richer than REST; long-lived tokens are user-scoped and not a
  service identity. TBD: a safe token strategy for multi-user installations.

## ThingsBoard

- Official: https://thingsboard.io/docs/, GitHub
  https://github.com/thingsboard/thingsboard, releases
  https://github.com/thingsboard/thingsboard/releases.
- Version: 4.4.1 (2026-11-24); 4.3.x is a maintenance LTS supported to
  2027-07-20.
- License: **changed** at 4.4 to Business Source License 1.1 (source-available,
  production free within device/server limits, commercial license beyond; each
  release converts to Apache-2.0 after four years). 4.3 CE remains Apache-2.0.
- Runtime: Java 25 from 4.4; Docker/Kubernetes deployment; REST and MQTT device
  APIs; rule engine, dashboards, multi-tenant customers.
- Security: device credentials, tenant/customer RBAC, API keys for WebSocket in
  4.4; advanced security is included.
- Use: adapter for enterprise deployments; do not bundle it in the default
  Device Control image. License/SBOM review is required before shipping.
- Limitations: source-available license, device limits, Java resource footprint;
  exact REST path/version for a deployment is TBD.

## EdgeX Foundry

- Official: https://www.edgexfoundry.org/, docs
  https://docs.edgexfoundry.org/4.0/, GitHub
  https://github.com/edgexfoundry/edgex-go.
- Version: 4.0.2 "Palau" (2026-05-29), 4.0 "Odesa" LTS.
- License: Apache-2.0 (LF Edge).
- Architecture: microservices; PostgreSQL default database in 4.0; Core Keeper
  replaces Consul; OpenBao replaces Vault; MQTT is the default message bus;
  Redis PubSub removed; device services for Modbus/OPC UA/BACnet, etc.
- Use: industrial edge adapter; Device Control should consume its device/event
  APIs or MQTT, not deploy EdgeX inside the core.
- Limitations: no native application UI; service topology and resource footprint
  are significant; security setup (OpenBao, TLS) is operational work. TBD:
  chosen device service/protocol for a pilot.

## Eclipse Mosquitto / MQTT

- Official: https://mosquitto.org/, GitHub
  https://github.com/eclipse-mosquitto/mosquitto, MQTT spec
  https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html.
- Version: 2.1.4 (2026-11-17; 2.1.3 was a critical security release).
- License: EPL-2.0 / EDL-1.0.
- Features: MQTT 5.0/3.1.1/3.1, TLS, ACL file/password plugins, bridges;
  no native clustering in open source.
- Use: optional transport for adapters and edge telemetry; not required for the
  Home Assistant pilot (REST/WebSocket).
- Security: tenant topic namespace, per-client ACL, TLS, no cross-tenant
  wildcards, no retained command topics, replay/duplicate handling. TBD:
  broker deployment and ACL backend.

## ESPHome

- Official: https://esphome.io/, GitHub https://github.com/esphome/esphome.
- Version: 2026.11.0.
- License: mixed — C++ runtime GPLv3, Python/tooling MIT. Commercial/distribution
  review required.
- Role: device firmware/native API source, not an IoT platform. It may become an
  endpoint adapter later; no direct Home Assistant dependency is assumed.
- Limitations: firmware lifecycle, OTA signing, device availability; GPLv3
  implications for distributed binaries. TBD.

## Decision inputs

- Home Assistant is the first pilot: permissive license, local-first, REST and
  WebSocket, easy fixture-driven contract tests.
- ThingsBoard must not be bundled without a license review due to BUSL 1.1.
- EdgeX is the industrial edge candidate after the HA pilot.
- Mosquitto is optional; adopt only after a PoC and security review.
- ESPHome is a device/firmware integration candidate, not a platform choice.
