# DC-012 Baseline and Gate

Date: 2026-11-27.

| Repo | HEAD | Notes |
| --- | --- | --- |
| device-control | `d084475` at start | HA adapter/SPI from DC-011 |
| mind-os | `0e9010cc` | Device Control provider module; live runtime unavailable |
| ai-platform | local `932cc0a` / origin `592c71b` | dirty pre-existing; foundation-storage/auth reused read-only |

DC-010 P0 remains **NO-GO** (real Android, Docker/TLS, live MindOS and restore
drill are BLOCKED). Therefore DC-012 is restricted to isolated development and
synthetic HA transport; **no real Home Assistant write or token is used**.
DC-011 architecture gate is PASS to enter DC-012.

## Implemented in this phase

- Platform instance, discovered device, claim/authorization and twin tables/API.
- Home Assistant REST adapter (discovery/state/service/read-back verification).
- Home Assistant pilot worker over the existing Device Control command channel.
- HA allowlist: `device.observe`, `light.turn_on`, `light.turn_off`,
  `light.set_brightness`; default claim is read-only.
- Pending/unclaimed discovery; claim creates the endpoint; write capability must
  be explicitly requested/authorized.
- Synthetic E2E: platform → discovery → claim → lease/approval → command →
  worker pulls/executes fake HA → state re-read → verified command.
- Secret references only; adapter token never in API responses/logs/tests.

## Gaps

- WebSocket event subscription/reconnect/replay is not implemented (REST +
  read-back only).
- Live HA version/auth/TLS/service verification, HA restart/network partition.
- Real postgres/S3 or platform instance adapter worker deployment.
- Platform manifest signing workflow for platform auto-provisioning is disabled
  in production; DC-010 gate must pass first.
- Telemetry ingestion/twin updates from HA events; MindOS live TaskRun UI E2E.
- Recorded RPO/RTO and Docker/HA tests.
