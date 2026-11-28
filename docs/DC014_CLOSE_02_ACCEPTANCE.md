# DC-014-CLOSE-02 Acceptance

Date: 2026-11-28
Pack: `DC-014-CLOSE-02_Runtime_Lifecycle_Hardening.zip`

## SHAs

| Repo | Baseline | Close-02 code commit |
|---|---|---|
| `device-control` | `6f3886f359177f2843d24d063c40383940fe9990` | `701fdd5b6ead8036d8bea59927ecb5285da90aa6` |
| `mind-os` | `e1362fa1a5705967ee1d50e837eb9b27f26c53b1` | `1903e176f2eff3dc1c663f0eb38aeee1140362a1` |

## Matrix

| ID | Gate | Priority | Result | Evidence |
|---|---|---:|---|---|
| C02-01 | TaskRun auto-acquires read_only Lease | P0 | PASS | Coordinator test asserts `read_only` acquire before submit |
| C02-02 | TaskRun auto-acquires control Lease | P0 | PASS | Write test asserts `control` acquire + approval/nonce |
| C02-03 | Lease retry/release/crash cleanup safe | P0 | PASS | One lease across retries; release on submit failure/terminal; no release while running/unknown; TTL fallback |
| C02-04 | HA Owner Lease renews | P0 | PASS | Store renewal test + bounded renewal thread (TTL/3) |
| C02-05 | Fencing rejects stale worker | P0 | PASS | Generation takeover + `stale_ingest_owner` storage rejection |
| C02-06 | Runtime Binding refresh applies revoke | P0 | PASS | Loader refresh removes entity; subsequent ingest ignored |
| C02-07 | Expired snapshot fails closed | P0 | PASS | Refresh failure past `valid_until` → `binding_expired`, no ingest |
| C02-08 | Tombstone survives container recreation | P0 | PARTIAL | Dedicated volume + state schema/corruption tests + restart test; actual container recreation BLOCKED |
| C02-09 | HA worker health/readiness works | P0 | PARTIAL | Health JSON + compose healthcheck + stopped/standby states tested; live Docker healthcheck BLOCKED |
| C02-10 | Production secrets/transport fail closed | P0 | PASS | Existing production config/write-off tests; compose dev profile explicitly not production |
| C02-11 | MindOS CI + Evidence Gates green | P0 | BLOCKED | Local gates pass; runs `46129214242`/`46129215362` logs unavailable |
| C02-12 | Real read TaskRun E2E | P0 | BLOCKED | No running MindOS/Device Control pair |
| C02-13 | Approved write TaskRun E2E | P0 | BLOCKED | No isolated HA |
| C02-14 | Multi-worker >2x TTL drill | P0 | PARTIAL | Renewal/takeover/stale-generation logic tested; wall-clock multi-process drill BLOCKED |

## Local verification

Device Control:

```
pytest                                                     # 236 passed
ruff check src tests gateway scripts                       # clean
mypy src/device_control gateway/src/device_gateway         # 42 files clean
OpenAPI                                                    # regenerated, no drift
```

MindOS:

```
pytest ../../tests ../../packages/contracts/tests            # 624 passed, 1 skipped
ruff check apps/api-gateway                                  # clean
mypy apps/api-gateway/app                                    # 746 files clean
pytest --collect-only                                        # 2333 collected
pytest packages/contracts/tests tests/contracts              # 291 passed
architecture guard / convergence / inventory / validation    # PASS
source truth + source release                                # PASS
```

## Environment

Docker, Home Assistant, Android/adb and GitHub Actions access are unavailable.
Remote CI/Evidence conclusions and all live drills remain **BLOCKED**, not PASS.
No tokens, nonces or secrets are recorded in this report.

## Conclusion

Code-level P0 lifecycle gates pass locally. C02-08/C02-09/C02-14 are partial
because the container/multi-process drills cannot run here; C02-11–C02-13 remain
BLOCKED. Overall **NO-GO**; production physical writes stay OFF.
