# Platform Selection Matrix (DC-011)

Scoring: 1 (weak) to 5 (strong) for this product's needs. License is a gate, not
just a score.

| Criterion | Home Assistant | ThingsBoard 4.4 | EdgeX 4.0 | Mosquitto | ESPHome |
| --- | ---: | ---: | ---: | ---: | ---: |
| Permissive license for default bundle | 5 Apache-2.0 | 2 BUSL-1.1 (4.3 CE Apache) | 5 Apache-2.0 | 4 EPL/EDL | 2 mixed GPLv3/MIT |
| Local-first / offline | 5 | 3 | 5 | 4 | 5 |
| Device/entity model richness | 5 | 5 | 4 | 1 | 2 |
| Command/service API | 5 REST/WS | 4 REST/MQTT | 3 device services | 2 pub/sub | 3 native API |
| Events/telemetry | 4 | 5 | 5 | 4 | 3 |
| Operational footprint | 4 | 2 Java 25 | 2 microservices | 5 | 5 firmware |
| Industrial protocols | 2 | 4 | 5 | 3 | 2 |
| Multi-tenant enterprise | 2 | 5 | 3 | 1 | 1 |
| Pilot speed for home/office | 5 | 3 | 2 | 3 | 3 |
| Supply-chain clarity | 5 | 2 | 5 | 4 | 2 |

## Recommendation

1. **Home Assistant** — DC-012 pilot. REST state/service plus WebSocket events;
   discovery pending/claim; re-read state for verification.
2. **EdgeX** — first industrial edge candidate after HA, using its device service
   and MQTT/event APIs through an adapter.
3. **ThingsBoard** — enterprise candidate only after legal/license review and a
   pinned 4.3 CE or commercial 4.4 decision; not in the default package.
4. **Mosquitto/MQTT** — optional adapter transport; requires ACL/TLS/replay PoC.
5. **ESPHome** — firmware/endpoint candidate, not a platform; GPLv3 review first.

## Hard gates

- No platform SDK in the core.
- Discovery never grants control authority.
- Every write goes through Device Control policy/approval/audit.
- Unknown platform fields/capabilities are rejected or quarantined.
- License/SBOM/signature required before an adapter is enabled in production.
