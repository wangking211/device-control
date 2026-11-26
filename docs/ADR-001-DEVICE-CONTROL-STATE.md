# ADR-001 — Device Control state, endpoints and abstractions

- Status: accepted
- Date: 2026-11-26
- Scope: `products/device-control` (standalone `wangking211/device-control`)
- Approval basis: DC-002–DC-005 Codex task pack, reviewed baseline
  `56de15b25f213f0d4e4811f672252174d9caff3c`

## Context

The reviewed service had endpoints, leases and approvals created by lazy
`CREATE TABLE IF NOT EXISTS`. DC-002 requires versioned migrations and atomic
authorization; DC-003–DC-005 require gateway identity, durable command
coordination, an outbox, audit and a separately deployable adapter process.
None of these exist in MindOS or ai-platform, and MindOS Task/TaskRun must
remain authoritative.

This ADR records why new tables, endpoints and abstractions are necessary, per
the ai-platform constraints in `AGENTS.md`.

## Decision

### New tables (all in `src/device_control/schema.py`)

| Table | Why reuse is insufficient | Consumers | Removal plan |
| --- | --- | --- | --- |
| `device_gateways` | Gateway identity/lifecycle is distinct from endpoint identity and from a MindOS Node; no existing table models it | gateway API, command dispatch, events, operator UI/CLI | drop when a platform-wide device registry with the same fields exists |
| `gateway_credentials` | Needs purpose (`enrollment`/`access`), expiry, rotation chain and revocation independent of endpoint credentials | gateway auth, rotation/revocation | same |
| `device_commands` | Device command state, dispatch metadata, idempotency and verification are product-owned; MindOS TaskRun must not be duplicated | command API, gateway pull/results, MindOS references | migrate to a shared durable job store if one supports device semantics; keep command ids as external refs |
| `command_transitions` | DC-005 requires an explicit audited transition history that terminal states never violate | audit/acceptance, incident review | derive from event log once an event store is authoritative |
| `command_events` (outbox) | Prevent DB/event dual-write loss; at-least-once delivery with consumer dedupe | MindOS/event consumers | replace with the platform event bus when its transactional outbox contract is adopted |
| `audit_records` | Security decisions (denials, approvals, revocations) need durable tenant-scoped audit | operators, security review | forward to platform audit sink and retain export |
| `schema_migrations` | Required to upgrade legacy databases without data loss | startup | standard |

No table duplicates knowledge points, skills, Evidence, Mastery, Practice,
LearningJourney, LearningEvent or MindOS Task/TaskRun. Commands store only
`task_ref`/`run_ref`/`correlation_id` references.

### Existing tables

`device_endpoints`, `device_leases`, `device_approvals` are extended in place.
Migration 1 adds columns with `ALTER TABLE` and rebuilds approvals once to add
the binding fields and the `invalidated` status, copying every legacy row. The
test `test_versioned_migration_preserves_legacy_records` asserts preservation.

### New endpoints

Each endpoint has a real consumer and tests:

- gateway lifecycle/pull/progress/result — `device_gateway` process and
  `gateway/tests/`; operators via `scripts/bootstrap_gateway.py`;
- command submit/status/cancel/evidence — MindOS integration client and
  `examples/mindos_client.py`;
- events/ack — MindOS polling consumer in `tests/test_commands.py`;
- metrics/audit/maintenance — operators (`docs/OPERATIONS.md`).

No endpoint returns raw screenshots or executes device actions.

### New abstractions (each has ≥2 users)

- `DeviceAdapter` port: `FakeAndroidAdapter` (tests/emulator CI) and
  `AndroidAdbAdapter` (real devices), plus a fail-closed `NullAdapter`.
- Gateway `Transport` port: urllib production transport and the in-process test
  transport.
- Versioned wire contracts: control-plane validation and gateway validation.

The gateway's bounded in-process queue is **not** a platform job queue/runtime.
It only buffers commands already admitted by the control plane, is intentionally
ephemeral, and applies backpressure; durable job execution remains outside this
product. Evidence is metadata (hashes/refs) only; there is no media factory or
binary store here.

## Consequences

- SQLite remains the store for this milestone; a future shared database must
  preserve tenant scoping, `BEGIN IMMEDIATE` semantics and migration evidence.
- Command/event retention and cleanup are explicit (`maintenance`,
  `DEVICE_CONTROL_EVENT_RETENTION_SECONDS`).
- Approval/command invalidation is transactional and may cancel in-flight work
  as `uncertain`; this is intentional and audited.

## Rollback

Stop the gateway, revoke gateways/endpoints, then drop the DC-003–DC-005 tables
and restore the pre-migration SQLite backup. Endpoint/lease/approval rows are
preserved by migration 1, so the rollback target is the old service code.
Secrets are not stored in the DB (only SHA-256 digests).
