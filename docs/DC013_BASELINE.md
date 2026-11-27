# DC-013 Baseline

Date: 2026-11-27.

| Repo | HEAD | Notes |
| --- | --- | --- |
| device-control | `c0c3923e584cc8b1adc0624dbf1676b9288090e5` | DC-012 synthetic pilot |
| mind-os | `0e9010ccd162da15d31ef7a0cdf741ba744f850d` | Device Control provider, no live runtime |
| ai-platform | local `f0ce6f7` / origin `0b80eec` | dirty pre-existing; not modified |

Fetched branches before work. DC-010 real-device/Docker/MindOS gates and DC-012
live HA gate remain BLOCKED, so DC-013 changes are isolated hardening and
synthetic/unit validation; no real HA or device write was performed.

## Audit result

- Pillow 12.3.0: pip-audit reported 42 advisories, fix 13.0.0 → upgraded.
- Bandit: 0 issues; targeted suppressions reviewed in
  `docs/DC013_01_SECURITY_REPORT.md`.
- HA worker only compared state hash when supplied → now mandatory for writes,
  with freshness and mapping checks.
- `HomeAssistantAdapter.subscribe()` returned empty events → WebSocket primitives
  implemented; ingestion integration remains a gap.
- Telemetry/twin were not persisted → migration 9 and APIs added.
- MindOS provider exists but no live TaskRun E2E.
