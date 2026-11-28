# DC-014-CLOSE Final Acceptance

Date: 2026-11-28
Task pack: `DC-014-CLOSE_Codex_Task_Pack.zip`

## Repository SHAs

| Repo | Baseline (fetched) | Close code commit |
|---|---|---|
| `wangking211/device-control` | `d341ebbb43f4fd213ab342cadc23e7f95567d20e` | `ac6c5623315a46ad3e018d64be49abcce54016c4` |
| `wangking211/mind-os` | `300fb06e77e5828ee09ad9314c4a97b56bd05dca` | `9b9c541e9566064cb45be204a9a78f4953cdb4e6` |

Both repositories were at the fetched `origin/main` before work; no newer
commit was overwritten. MindOS retains two pre-existing untracked local files
(`.local-dev/`, a D0 audit note) that were intentionally not committed.

## Per-task status

| Task | Status | Evidence / limitation |
|---|---|---|
| 00 Baseline, CI root cause, reproduction | PARTIAL | `artifacts/dc014-close/baseline.json`, `ci-failure-analysis.md`, `reproduction.md`; four reproducible failures fixed. Remote job logs **BLOCKED** (no `gh`/token) |
| 01 Read/Write lease contract | PASS | `tests/test_lease_matrix.py`: read lease read, no/expired/cross-tenant lease, read lease + write, missing approval, bad nonce, valid write, audited release |
| 02 Binding revision and trust edge | PASS | Mandatory exact `binding_revision`; signed document (scope, revision, nonce, validity); `tests/test_binding_document.py` covers forged/expired/cross-scope/replay/stale/conflict/atomic failure |
| 03 Real TaskRun integration | BLOCKED (live) | Coordinator + lease release exist (`mind-os/tests/test_device_task_run_dc014.py`); no running MindOS/Device Control pair to prove a real TaskRun |
| 04 Provider/OpenAPI/API conformance | PARTIAL | Shared submit fixture validates against the command schema and live test API; command detail/cancel/evidence response fields asserted; a true two-service smoke run is BLOCKED |
| 05 MindOS CI / Evidence Gates repair | PARTIAL | Local CI-equivalent suite green; remote CI and Evidence Gate URLs **BLOCKED** (no GitHub access) |
| 06 HA WebSocket lifecycle | PARTIAL | Persisted cursor/dedupe/gap/auth-invalid exist; added persisted single-writer owner lease; live HA restart/partition drill **BLOCKED** |
| 07 Docker + isolated HA E2E | BLOCKED | `docker` not installed; compose profile not executed |
| 08 Device management UI | BLOCKED | No browser/frontend runtime in this environment |
| 09 Android E2E | BLOCKED | `adb` not installed; no emulator/device |
| 10 Production readiness | PARTIAL | Missing secrets fail closed, writes default OFF, readiness reports config errors; key rotation/backup/RPO/RTO drills **BLOCKED** |

## Test evidence (local)

Device Control:

```
python -m pytest -q                                      # 221 passed
ruff check src tests gateway                             # clean
mypy ... --ignore-missing-imports --no-site-packages     # 42 files, clean
bandit -c .bandit -r src gateway/src                     # no issues
pip-audit -r requirements/audit.txt                      # no known vulnerabilities
python scripts/export_openapi.py                         # no drift
```

MindOS (from `apps/api-gateway`):

```
python -m pytest -q ../../tests ../../packages/contracts/tests   # 611 passed, 1 skipped
python scripts/architecture_guard.py --strict                    # PASSED
python scripts/repository_convergence_check.py                   # PASS
python scripts/source_release_check.py --check --tracked-only    # PASS
python scripts/generate_source_truth.py --check                  # PASS
```

## CI / Evidence Gates

No run URL or check result is recorded because GitHub access is unavailable.
This is an explicit evidence gap, not a PASS. The fixes are limited to failures
that were reproduced locally; the remote conclusion must be updated from a
GitHub-authorized machine.

## Environment

| Capability | State |
|---|---|
| Home Assistant | unavailable |
| Docker / compose | unavailable |
| Android device/emulator | unavailable |
| Production/staging | unavailable |
| GitHub CLI/token | unavailable |

## Safety state

- Physical writes remain **default OFF** in production
  (`DEVICE_CONTROL_ENABLE_WRITES` must be set explicitly).
- Production startup fails when identity, manifest, redaction or binding
  signing configuration is missing.
- `unknown` write commands are never auto-replayed.
- Binding documents are signed and rejected on forged/expired/stale/replayed
  content.
- MindOS still stores only Device Control Evidence references.

## Conclusion

**P0 code gates pass locally; the end-to-end definition of done is NOT met.**
Docker + isolated HA, a real MindOS TaskRun, Android, remote CI and production
recovery drills are still BLOCKED. Production writes remain disabled and the
overall status is **NO-GO** until those environment-bound gates are executed
with sanitized evidence.
