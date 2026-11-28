# DC-014-CLOSE-02 Runtime Lifecycle Notes

Date: 2026-11-28
Repos: `device-control`, `mind-os`

## TaskRun Lease lifecycle (01)

Order is always: trusted capability risk → lease mode → acquire → validate →
submit → outcome. The coordinator does not trust a caller `lease_mode`; a
caller-supplied lease is read back and checked for endpoint, mode, task and
active state. A new run acquires:

- `read_only` for `risk_tier=read`
- `control` for `write`/`destructive`/`safety_critical`

One lease is reused across transport/5xx retries. It is released when submit
fails before acceptance and after a terminal outcome; it is **not** released for
`running`, `verifying`, `queued`, `waiting_approval` or `unknown`, because the
command may still execute. Lease expiry is the durable crash fallback.

Device Control adds `GET /v1/device-leases/{id}` for TaskRun verification and
reconnect; it is tenant-scoped and endpoint-scope checked.

## HA owner fencing (02)

`ha_ingest_state.owner_generation` is the fencing token.

- Acquire by a new owner increments the generation.
- Renewal is atomic and scoped to `(tenant, platform, owner_ref, generation)`.
- A renewal thread runs every `owner_ttl/3`; on failure it marks ownership
  lost, closes the WebSocket and stops ingestion.
- `record_ha_event` / `record_ha_gap` reject writes from a stale owner or
  generation at the storage layer, not only by cooperative shutdown.
- Metrics expose owner, generation, lease expiry, last event/reconcile, gap
  count and lag.

## Binding refresh (03)

The managed worker refreshes the signed snapshot periodically
(`HA_BINDING_REFRESH_SECONDS`, default 60). Each refresh verifies signature,
key id, scope, validity, nonce and monotonic revisions via
`BindingRegistry.load_document`, then atomically replaces the entity map.

- Omitted/revoked entities stop being ingested immediately.
- A refresh failure keeps the last snapshot only until its signed
  `valid_until`; after that the worker exits `binding_expired`.
- State/tombstones persist with schema `1`; corrupt or cross-scope state fails
  closed.

## Persistence, health and deployment (04)

- State and health live under `/var/lib/device-control-ha` on a dedicated
  compose volume, not tmpfs.
- Writes are atomic and attempt mode `0600`.
- The worker writes a health JSON (`connected`, `standby`, `failed`, etc.)
  used by the compose healthcheck.
- Exit codes: `0` stopped, `2` auth_invalid, `3` standby, `4` ownership_lost,
  `5` binding_expired.

Compose remains a **development/isolated** profile: it uses local HTTP and
dev-default secrets. It is not a production deployment; production still fails
closed on missing secrets and keeps writes off.

## Tests added

- `tests/test_binding_document.py`: corruption/scope fail-closed.
- `tests/test_ha_ingest.py`: owner renewal, takeover generation, stale
  generation rejection, binding refresh revocation, expired snapshot,
  health file.
- `tests/test_lease_matrix.py`: lease status endpoint and tenant scope.
- MindOS `test_device_task_run_dc014.py`: auto-acquire read/control, caller
  lease verification, retry reuse, release policy.
