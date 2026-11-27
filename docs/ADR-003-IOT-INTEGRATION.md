# ADR-003 — IoT Platform Integration Architecture

- Status: accepted (design gate; implementation limited to SPI/contracts)
- Date: 2026-11-27
- Context: DC-011; DC-010 is still NO-GO for production execution.

## Decision

MindOS → Device Control Unified API → Domain Core → Adapter SPI → external
IoT platform/protocol/edge gateway → physical devices.

### 1. Domain ownership

Device Control is the canonical fact source for device identity, trust, leases,
approvals, commands, twin/evidence metadata and policy. External platforms keep
their native data and automations; native ids are mapped, never used as canonical
ids or authorization. A discovered device is `pending` and cannot execute until
claimed and trusted.

### 2. Adapter deployment

Adapters are separate from the core API. Preferred production mode is an
isolated worker/edge process; in-process is for development and simple
deployments. The core never imports a platform SDK. The adapter worker may use
platform SDKs/MQTT clients. A crash/timeout opens a circuit and does not take
down the API.

### 3. Model and extensions

Canonical entities: PlatformInstance, AdapterInstance, Device, Gateway,
Endpoint, Capability, Property, Telemetry, Event, Command, Twin, EvidenceReference,
NativeMapping, DeviceGroup/Location. Native extension fields are bounded and
versioned; unknown platform fields are quarantined, not merged into core
metadata. One logical device may map several native devices only with an explicit
conflict policy.

### 4. Command authority

External platform service calls are never issued directly by MindOS or an agent.
Every write becomes a Device Control command after policy, lease and approval;
the adapter receives the command only after authorization. Adapter `accepted`
or a platform HTTP 2xx is not physical success; the adapter must observe/re-read
and report verification, otherwise `executed_unverified`/`uncertain`.

### 5. Telemetry/events

Telemetry has source and ingest timestamps, sequence, quality and adapter/schema
version. Duplicates are idempotently dropped by `(source, device, metric,
sequence)`; out-of-order/late data is retained with quality, not used as a safety
interlock. Events use the existing platform envelope shape and at-least-once
delivery with consumer dedupe; ordering is per aggregate only. Backpressure is
bounded and drops oldest/lowest-value telemetry before commands.

### 6. Twin

`desired`, `reported` and `observed` are separate records with source/time/quality/
version. No last-write-wins for safety state. Desired values expire; after offline
recovery they are re-evaluated before execution. Expired/uncertain non-idempotent
commands are never replayed.

### 7. Tenant/credential isolation

Platform instances, adapter instances, devices, telemetry, twins and evidence are
tenant-scoped. Platform credentials are secret references resolved server-side.
Agents and MindOS never receive platform admin credentials. A platform instance
delete/disable revokes credentials/leases/approvals with audit, but does not
silently delete devices/evidence.

### 8. License/supply chain

Adapters declare license, SBOM, publisher and Ed25519 signature. A platform
license gate is explicit: Home Assistant Apache-2.0; ThingsBoard 4.4 BUSL-1.1
(4.3 CE Apache-2.0); EdgeX Apache-2.0; Mosquitto EPL/EDL; ESPHome mixed
GPLv3/MIT. No platform source is merged. Third-party images/SDKs are pinned and
scanned.

## Alternatives

- Direct MindOS → platform API: rejected (duplicate policy, credentials leak,
  no unified audit).
- Every platform embedded in Device Control: rejected (fat core, license/SDK
  coupling, upgrade risk).
- Separate per-platform command engines: rejected (duplicate state machines).
- MQTT-only core: rejected (loses request/response, auth and multi-platform
  semantics; MQTT remains an adapter transport).

## Consequences / rollback

- The adapter SPI/lifecycle is new stable surface; version it (`api_version=1.0`).
- No DB migration in this phase; canonical records will require a later ADR with
  consumers and migration/rollback evidence.
- Removing an adapter must disable it, revoke credentials, invalidate approvals/
  leases, and preserve audit/evidence references.
