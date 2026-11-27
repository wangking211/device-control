# DC-011 Baseline

Date: 2026-11-27. Rebased against the latest fetched main branches.

| Repo | HEAD | Working tree | Notes |
| --- | --- | --- | --- |
| device-control | `8039a26d0ad99c94f8a9ac2254860958b7d86efa` | clean at start | DC-010 code is the current base |
| mind-os | `0e9010ccd162da15d31ef7a0cdf741ba744f850d` | pre-existing untracked local-dev/docs | Device Control provider added in DC-010 |
| ai-platform | local `932cc0a` / origin `592c71b` | pre-existing dirty tree; not rebased | foundation-storage/auth inspected read-only |

## DC-010 gate check

`acceptance/DC010_ACCEPTANCE.md` and `GO_NO_GO.md` remain **NO-GO** because real
Android, Docker/TLS/mTLS, live MindOS and a production restore drill are
BLOCKED. Therefore this phase is limited to architecture, contracts, SPI,
fixtures and isolated tests; no production execution path is enabled and no
external platform credential/device is used.

## Current Device Control assets inspected

`Device`, `Gateway`, `Endpoint`, `Manifest`, `Capability`, policy, approval,
lease, `Command` state machine, events/outbox, evidence metadata/content,
diagnostics, alerts and OpenAPI. The existing `device_commands` state machine is
the authority; DC-011 adds an adapter boundary and canonical contracts rather
than a second command engine.

## Reuse boundaries

- ai-platform: identity/scoped service tokens, `foundation-storage`, event
  envelope, observability/metrics conventions.
- MindOS: Task/TaskRun, approval UX, provider registry; calls Device Control only.
- device-control: canonical device/platform/adapter/twin/command/telemetry/event
  ownership.
- External platform: native connectivity, protocol drivers, automations and
  telemetry; adapter translates but does not own policy.

## Gaps / TBD

- ThingsBoard exact REST/MQTT auth paths and provisioning scope: TBD vendor docs
  per deployment version.
- EdgeX device-service coverage for a specific industrial protocol: TBD site.
- Home Assistant WebSocket event schema for every entity domain: TBD per
  integration; REST state/service subset is specified for the pilot.
- MQTT broker choice and ACL backend: TBD deployment.
- No external platform was contacted; live discovery/commands are BLOCKED.
