# DC-014-CLOSE-01 Acceptance

Date: 2026-11-28
Pack: `DC-014-CLOSE-01_Integration_and_Binding_Fixes.zip`

## SHAs

| Repo | Baseline | Close-01 code commit |
|---|---|---|
| `device-control` | `0e04482789a6cae566168d6d30103be62259115c` | `d08baed6bac1dcdedd32d13aa6d942f5ceefaf36` |
| `mind-os` | `9b9c541e9566064cb45be204a9a78f4953cdb4e6` | `e1362fa1a5705967ee1d50e837eb9b27f26c53b1` |

## Matrix

| ID | Gate | Priority | Result | Evidence |
|---|---|---:|---|---|
| C01-01 | MindOS read Lease mandatory | P0 | PASS | `test_read_without_lease_is_rejected_before_http`; provider refuses empty lease before HTTP |
| C01-02 | read_only/control mode enforced | P0 | PASS | Coordinator lease-mode checks + `tests/test_lease_matrix.py` |
| C01-03 | write approval/nonce retained | P0 | PASS | Write tier requires approval + nonce; read rejects approval |
| C01-04 | per-device revision cannot regress | P0 | PASS | `binding_revision_regression` on documents and `bind()` |
| C01-05 | removed/revoked binding invalidates old commands | P0 | PASS | Snapshot omission → tombstone → worker rejects `binding_revoked`, zero HA calls |
| C01-06 | snapshot/delta semantics explicit | P0 | PASS | `docs/ADR-004-BINDING-SNAPSHOT-SEMANTICS.md` + signed snapshot tests |
| C01-07 | HA worker auto-starts under supervisor | P0 | PARTIAL | `ha-event-worker` compose service + dedicated script + static compose tests; Docker run BLOCKED |
| C01-08 | owner lease/restart/multi-replica safe | P0 | PARTIAL | Owner lease + standby + takeover + restart tombstone tests; live two-replica drill BLOCKED |
| C01-09 | MindOS CI green | P0 | BLOCKED | Local ruff/mypy/collect/contracts pass; no remote run URL or logs |
| C01-10 | Evidence Gates green; Release Evidence runs | P0 | BLOCKED | Local gate commands pass; remote Evidence run and artifact unavailable |
| C01-11 | real MindOS read TaskRun | P0 | BLOCKED | No running MindOS + Device Control pair |
| C01-12 | approval-gated write TaskRun | P0 | BLOCKED | No isolated HA instance |
| C01-13 | unknown outcome never replayed | P0 | PARTIAL | Coordinator/test proof; response-loss live E2E BLOCKED |
| C01-14 | production writes default OFF | P0 | PASS | `tests/test_production_gate.py`; production config fail-closed |

## Local verification

Device Control:

```
python -m pytest -q                                      # 230 passed
ruff check src tests gateway scripts                     # clean
mypy ... --ignore-missing-imports --no-site-packages     # 42 files clean
bandit / pip-audit / OpenAPI drift                       # clean
```

MindOS:

```
python -m pytest -q ../../tests ../../packages/contracts/tests   # 619 passed, 1 skipped
python -m ruff check apps/api-gateway                            # clean
mypy apps/api-gateway/app                                        # 746 files clean
python -m pytest -q --collect-only                               # 2328 collected
python -m pytest -q packages/contracts/tests tests/contracts     # 291 passed
architecture / registry / authority / layer / route / source truth # PASS
```

## Environment limits

Docker, Home Assistant, Android/adb, and GitHub Actions access are unavailable.
Remote CI and Evidence Gate conclusions are therefore **BLOCKED**, not PASS.
Release-context boundary failures seen locally come from untracked generated
copies and do not occur in a clean clone.

## Conclusion

`C01-01`–`C01-06` and `C01-14` pass locally. `C01-07`, `C01-08` and `C01-13`
are partially proven code-side but lack the required live Docker/HA/TaskRun
drill. `C01-09`–`C01-12` remain BLOCKED. Overall: **NO-GO**; production writes
stay disabled.
