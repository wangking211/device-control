# Approval Binding and Replay (DC-006)

An approval is a capability ticket for one exact action. The digest binds:

- tenant, endpoint, device id and device fingerprint, gateway;
- capability id/version and manifest `operation`;
- canonical parameters (sorted JSON), intent;
- state hash and state version;
- requester, lease, policy version, manifest digest;
- a one-time `approval_nonce`;
- expiry.

The approver is the verified principal; any `approver_ref` in the request is
ignored. Self-approval is denied by default.

## Consumption

`_consume_approval_tx` runs inside the same `BEGIN IMMEDIATE` transaction as
command insertion:

1. approval exists for the tenant and is `approved`, unexpired, unused;
2. recomputed digest/nonce/state/device/endpoint/capability all match;
3. endpoint is not offline/revoked and the lease is still active;
4. `UPDATE ... WHERE status='approved'` must affect exactly one row;
5. command, transitions, audit and outbox are inserted; otherwise rollback.

Concurrent callers serialize on the SQLite write lock. Exactly one succeeds;
the other receives `409 approval_not_consumable` or `approval_binding_mismatch`.

## Invalidation

Approval request and decision revalidate endpoint/lease. Endpoint or gateway
revocation, lease release/expiry, and command cancellation by state invalidation
mark pending/approved approvals `invalidated`. A late approval cannot be used
after the device identity, manifest, parameters or state changed.

## Migration

Migration 5 adds the new binding columns with defaults. Approvals created before
DC-006 are preserved but cannot satisfy the new digest (empty operation/device/
nonce); they must be re-requested. This is intentional fail-closed behavior.

## Non-goals

- Device Control does not provide the human approval UI; MindOS does.
- An approval is not a capability grant for future actions; it is consumed once.
