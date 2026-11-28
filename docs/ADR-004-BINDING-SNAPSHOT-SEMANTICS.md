# ADR-004: Signed Binding Documents Are Complete Snapshots

Status: Accepted (DC-014-CLOSE-01)
Repo: `device-control`

## Decision

`dc-binding-document/v1` is a **complete snapshot**, never a partial delta. The
`bindings` array is the full active set for one tenant/gateway/platform scope.

- A document with an empty `bindings` array is valid and revokes every binding
  in that scope.
- Any entity omitted from a newer snapshot is removed from the active set and
  recorded as a tombstone `(last_device_revision, document_revision, revoked_at)`.
- A re-added entity must come from a newer document revision and carry a
  strictly newer per-device revision than its tombstone.
- Per-device revisions are monotonic. Equal revision is accepted only when the
  endpoint, device and capability set are unchanged; otherwise the document is
  rejected as a conflict.
- `bind(revision=...)` and `revoke()` reject non-increasing replacement
  revisions.
- Validation is atomic: every item is parsed and checked into a temporary map
  before the registry replaces its state. A failure at item N leaves item 1..N-1
  unapplied.
- Signature, key id, scope, issue/expiry window and nonce anti-replay remain
  mandatory. Omitted entities and tombstones are persisted to the optional edge
  state file and survive restart.

## Why snapshot

The control plane already knows the complete claimed set for a gateway. A
delta protocol would require a second operation log and reconciliation state,
which is more failure modes for the same authority. Snapshot makes revocation
of a removed device explicit and testable.

## Rejected alternative

Partial delta with explicit upsert/revoke operations. Rejected because the
control plane would need to persist delta sequencing per edge, and a missed
delta would silently keep a revoked device authorized.

## Compatibility

The schema name is unchanged for already-issued documents, but consumers must
treat omission as revocation. The edge state file is optional; without it the
registry reloads the signed snapshot on startup. TTL still bounds any cached
document.
