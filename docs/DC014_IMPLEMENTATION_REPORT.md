# DC-014 Implementation Report

Date: 2026-11-28
Task pack: `DC-014_Live_Device_Integration_MindOS_Task_Pack.zip`

## Commits

| Repo | Commit | Scope |
|---|---|---|
| device-control | `116445d` | 014-00 baseline, 014-01 binding, 014-02 status projection |
| device-control | `65aa1fa` | 014-05 durable HA ingestion, 014-06 convergence |
| device-control | `22106ec` | acceptance matrix + canonical normalization |
| mind-os | `300fb06e` | 014-00 CI recovery, 014-02/03/04 provider integration |

Remote `main` was fetched before work; no newer commit was overwritten.

## Task status

| Task | Status | What landed |
|---|---|---|
| 014-00 Baseline / MindOS CI | PARTIAL | Real SHA baseline, reproducible CI root-cause fixes; remote CI logs/status BLOCKED (no `gh`/token) |
| 014-01 Worker binding fail-closed | PASS | `BindingRegistry`; all identity fields mandatory; revoked/expired/revision-stale rejected before HA POST |
| 014-02 Command state contract | PASS | One canonical projection on both sides; `provider_status` preserved; `executed_unverified→verifying`; unknown→unknown |
| 014-03 Provider Registry | PARTIAL | Catalog entry resolved by `RuntimeAuthorityResolver`; factory + secret refs + SSRF guard; live health BLOCKED |
| 014-04 TaskRun lifecycle | BLOCKED (live) | Thin coordinator with idempotency, approval gates, cancel `too_late`, evidence refs; no live MindOS TaskRun |
| 014-05 WS durable pipeline | PARTIAL | Persisted event log/cursor, dedupe, gap marker, reconnect reconciliation, auth-invalid stop; live HA BLOCKED |
| 014-06 Telemetry/Twin convergence | PASS | observed/received separation, late/future handling, per-device freshness |
| 014-07 Claim/authorize UI | BLOCKED | No browser/frontend runtime; API claim/read-only already tested |
| 014-08 Docker + HA E2E | BLOCKED | `docker` not installed; compose not executed |
| 014-09 Android E2E | BLOCKED | `adb` not installed; no emulator/device |
| 014-10 Production readiness | PARTIAL / BLOCKED | Missing production secrets fail closed at startup and writes default OFF; key rotation, backup/RPO/RTO and failure drills BLOCKED |

## Verification actually run

Device Control:

```
python -m pytest -q                    # 194 passed
ruff check src tests gateway           # All checks passed
bandit -r src/device_control            # No issues identified
python -m mypy <new modules> --python-version 3.12
```

MindOS (from `apps/api-gateway`):

```
python -m pytest -q ../../tests ../../packages/contracts/tests   # 610 passed, 1 skipped
python scripts/architecture_guard.py --strict                    # PASSED
python scripts/repository_convergence_check.py                   # PASS
python scripts/source_release_check.py --check --tracked-only    # PASS
python scripts/generate_source_truth.py --check                  # PASS
```

mypy note: the environment has mypy 2.3.1 with newer `cryptography` stubs that
flag pre-existing `public_key.verify` union-attr calls in `iot/manifest.py` and
`app.py`. The new modules are clean; this is dependency-stub drift, not a
DC-014 change.

## Key safety properties

- Missing/empty/forged tenant, gateway, platform, endpoint or device identity
  fails closed; a partial envelope cannot skip a mapping check.
- Writes require lease + approval id + nonce + upstream `ask`; reads still
  enforce tenant/device identity.
- Rejected commands never call the HA service endpoint.
- `executed_unverified` never projects to `succeeded`; `uncertain` never
  auto-replays.
- Duplicate HA events are idempotent; attribute-only changes are distinct;
  late events cannot roll the twin back; future timestamps are clamped.
- Only claimed entities of the exact tenant/platform are ingested.
- MindOS uses the existing runtime registry and Device Control Evidence store;
  it creates no second registry, task engine, policy, twin or evidence store.
- Production configuration validates identity/manifest/redaction secrets at
  startup; physical writes are OFF unless `DEVICE_CONTROL_ENABLE_WRITES` is
  explicitly enabled.

## Risks / open items

1. **Remote CI unverified.** The local CI-equivalent suite is green, but the
   new MindOS run must be observed from a GitHub-authorized machine.
2. **No live HA.** Durable ingestion, reconnection, auth failure and command
   verification are proven synthetically only.
3. **No live TaskRun.** Coordinator behavior is unit-tested; end-to-end
   Task→TaskRun→submit→get→evidence is not proven.
4. **No Docker/Android.** 014-08/09/10 remain blocked; real writes stay off.
5. **Binding freshness.** Edge bindings have a TTL; a production deployment
   must refresh them before expiry and surface `binding_expired` as a
   reconnect/refresh signal.

## Start conditions for the next task

- 014-05 live closure: an isolated HA instance with a scoped token, Docker
  available, and sanitized logs.
- 014-04 closure: running Device Control + MindOS API with a test tenant.
- 014-08: Docker daemon and the isolated compose file; never production HA.
- 014-09: an Android emulator/device with the approved test app.
- 014-10: staging environment plus approved key/backup drill window.

Overall: **NO-GO for production writes.** P0 local code gates pass; live
environment gates are BLOCKED.
