# ADR-002 — Manifest authority, device binding, approval v2 and evidence

- Status: accepted
- Date: 2026-11-26
- Scope: DC-006–DC-009
- Related: ADR-001, `docs/BASELINE_AUDIT.md`

## Context

The DC-002–DC-005 baseline accepted endpoint-reported risk and any
`verification.verified=true`, had no physical device binding, no rich UI state,
no evidence bytes, and manifest risk could be downgraded by an envelope. DC-006
makes these release blockers; DC-007–DC-009 require evidence storage and
operations.

## Decisions

1. **Manifest authority.** A trusted, versioned manifest per gateway defines
   capability id/version, operation, risk, input schema, state requirements and
   verification. It is registered by an operator (`PUT /v1/gateways/{id}/manifest`),
   stored with digest/signature and revision history, and reported in heartbeat.
   Control plane uses manifest risk/capability; gateway revalidates digest,
   operation, risk and parameters. Endpoint capability reports are observations,
   not authority.
2. **Device binding.** Endpoint gets `device_id`/`device_fingerprint`; gateway
   creation/manifest pins one endpoint/device. Gateway configuration supplies
   the local endpoint id and fingerprint; envelope endpoint/device must match
   observed state and configured values.
3. **Approval v2.** Digest additionally binds operation, device id/fingerprint,
   state version, manifest digest and a one-time nonce. Commands must present
   the nonce. Consumption remains atomic with command insertion.
4. **State and verification.** Gateway returns redacted UIAutomator node
   summaries, source/quality/observed_at, content-state hash and version. State
   dependent capabilities require both and a max age. Adapters derive sensitive
   control properties from node attributes. `executed_unverified` maps to
   command `uncertain`; success requires capability-defined verification.
5. **Isolation.** Production adapters run in a spawned child process per call
   with hard terminate/kill; a killed action is uncertain and non-idempotent
   work is not replayed.
6. **Evidence.** New `device_evidence` table stores metadata only; bytes live
   behind an `ObjectStore` port (local FS adapter for dev). Upload/download are
   gateway/tenant authorized, hashed, redacted/retention checked and audited.

## New tables/endpoints and reuse justification

- `gateway_manifest_revisions`: audit of manifest revisions; cannot be derived
  from a single current row. Consumers: operator/diagnostics/audit.
- `device_evidence`: metadata for object-store bytes; SQLite never stores the
  binary. Consumers: command evidence UI/API, retention/backup.
- New endpoint surface (`manifest`, `diagnostics`, `alerts`, evidence upload/
  content/delete, `/admin`) has real consumers in tests, scripts and the
  MindOS provider. No endpoint replaces an existing one.
- No Task/TaskRun, identity, queue, scheduler or object-storage duplicate is
  introduced; command refs remain external.

## Consequences

- Existing approvals/commands created before migration 5 lack new binding fields
  and must be re-created; rows are preserved.
- Manifest rotation invalidates dispatch until the gateway reports the new
  digest; this is fail-closed.
- The evidence local filesystem adapter is not production-durable; production
  supplies an object-store implementation.

## Rollback

Stop the gateway, revoke gateways/endpoints, restore the pre-migration SQLite
backup and evidence backup, then deploy the previous control-plane/gateway
images. Credential digests only are in the DB; rotate identity/manifest keys if
compromise is suspected.
