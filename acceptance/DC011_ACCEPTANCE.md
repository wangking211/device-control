# DC-011 Acceptance Matrix

Date: 2026-11-27. Automated suite: **110 passed** (DC-010 102 + 8 IoT SPI
tests); Ruff/mypy/Bandit clean locally. No external platform, broker, HA
instance, Docker or device was used.

| ID | Requirement | Priority | Status | Evidence |
|---|---|---:|---|---|
| D11-001 | Three-repo baseline and DC-010 gate | P0 | PASS | `docs/DC011_BASELINE.md`; DC-010 NO-GO recorded; production path blocked |
| D11-002 | Official platform versions/licenses | P0 | PASS | `docs/OPEN_SOURCE_PLATFORM_RESEARCH.md` (verified 2026-11-27, URLs) |
| D11-003 | Architecture/ADR | P0 | PASS | `docs/ADR-003-IOT-INTEGRATION.md` |
| D11-004 | Core has no platform SDK dependency | P0 | PASS | `src/device_control/iot` imports only stdlib/jsonschema/cryptography; SPI tests |
| D11-005 | Adapter SPI + plugin manifest | P0 | PASS | `iot/spi.py`, `adapter-plugin-manifest.schema.json`, `tests/test_iot_spi.py` |
| D11-006 | Lifecycle/isolation/resource limits | P1 | PARTIAL | lifecycle/timeout/circuit tests; no live process CPU/RAM/network isolation |
| D11-007 | Canonical Device Model | P0 | PASS (design/contract) | `canonical-device.schema.json`, model contract tests; no DB migration yet |
| D11-008 | Capability risk/approval/verification semantics | P0 | PASS (design) | SPI mappings + existing DC-006/010 manifest risk tests |
| D11-009 | Command state/idempotency contract | P0 | PASS (existing + mapping) | existing command tests; external states mapped in ADR/API docs |
| D11-010 | Telemetry/event dedupe/out-of-order/backpressure | P1 | PARTIAL | telemetry schema/topic helper; ingestion pipeline not implemented |
| D11-011 | Twin desired/reported/observed | P1 | PARTIAL | `device-twin.schema.json`; persistence/conflict service not implemented |
| D11-012 | Unified API/OpenAPI | P0 | PARTIAL | logical API design; existing OpenAPI unchanged, new endpoints deferred to DC-012 |
| D11-013 | MindOS only uses unified API | P0 | PASS (design/code) | MindOS provider from DC-010; no platform-native call |
| D11-014 | Tenant/credential isolation | P0 | PARTIAL | design + existing tenant tests; platform secret_ref resolver not implemented |
| D11-015 | Edge profiles/offline policy | P1 | PARTIAL | documented profiles/rules; no measurements |
| D11-016 | MQTT ACL/TLS/replay | P1 | PARTIAL | topic/ACL/retained helper + tests; no broker PoC/TLS |
| D11-017 | Home Assistant pilot spec/fixtures | P1 | PASS (spec) / BLOCKED (live) | `docs/HOME_ASSISTANT_PILOT.md`, fixture and mapping tests; no HA instance |
| D11-018 | License/SBOM/supply chain | P1 | PARTIAL | manifest license/SBOM/signature fields; SBOM pipeline pending |
| D11-019 | Contract/compat/fault-injection tests | P1 | PASS (isolated) | SPI contract, timeout/circuit, schema tests; no live platform fault |

## Gate decision

Design gate: **PASS to enter DC-012** for the Home Assistant pilot specification
and isolated implementation. Production/IoT GO: **NO-GO** until DC-010 P0
hardware/Docker/MindOS blockers and D11-006/010/011/014/016/017/018 live items
are executed. No external platform source, credential or real device was used.
