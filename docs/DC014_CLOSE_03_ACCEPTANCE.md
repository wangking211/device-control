# DC-014-CLOSE-03 Acceptance

Date: 2026-11-28
Pack: `DC-014-CLOSE-03_Integration_Closure_Security_Gate.zip`

## SHAs

| Repo | Baseline | Close-03 code commit |
|---|---|---|
| `device-control` | `d776dfc1349c6fbaa6004ce28ed41ebec2012242` | `070c975b36bffe1eaf451faec7ddcf02fca954fd` |
| `mind-os` | `1903e176f2eff3dc1c663f0eb38aeee1140362a1` | `c698ce8dd20b85d2d51ee708820e90536201b887` |

## Matrix

| ID | Gate | Priority | Result | Evidence |
|---|---|---:|---|---|
| C03-01 | Bandit B110 fixed without suppression | P0 | PASS | Idempotent close, narrow expected errors, sanitized logging; `bandit -c .bandit` no issues |
| C03-02 | pip-audit explicitly passes | P0 | PASS | `pip-audit -r requirements/audit.txt` → no known vulnerabilities |
| C03-03 | Expired same-owner Lease increments generation | P0 | PASS | Same-name new incarnation and same-incarnation expiry both increment |
| C03-04 | Expired Lease cannot renew or ingest | P0 | PASS | Renew returns `lease_expired`; storage rejects stale generation/expiry |
| C03-05 | Real TaskRun invokes DeviceRunCoordinator | P0 | BLOCKED | Canonical path enqueues AgentTask; Agent Node drivers are TS; no production call site (see runtime note) |
| C03-06 | Lease/command state durable across crash | P0 | PARTIAL | `DeviceRunState` durable projection + tests; no real TaskRun persistence/crash drill |
| C03-07 | run_ref/tenant/holder scope verified | P0 | PASS | Caller lease checks tenant/task/run/holder/endpoint/mode/active |
| C03-08 | terminal callback releases Lease | P0 | PARTIAL | `complete()` release policy tested; no real TaskRun terminal callback |
| C03-09 | unknown outcome reconciles without replay | P0 | PARTIAL | Poll-only reconcile and no resubmit proven in tests; live response-loss BLOCKED |
| C03-10 | MindOS CI green | P0 | BLOCKED | Local gates pass; run `46132730981` logs unavailable |
| C03-11 | MindOS Evidence Gates + Release Evidence green | P0 | BLOCKED | Run `46132731983`; no logs/artifact access |
| C03-12 | Real read TaskRun E2E | P0 | BLOCKED | No running MindOS + Device Control pair |
| C03-13 | Approved write TaskRun E2E | P0 | BLOCKED | No isolated HA |
| C03-14 | HA worker restart/fencing drill | P0 | PARTIAL | Incarnation/fencing/concurrency tests; container restart drill BLOCKED |

## Local verification

Device Control:

```
pytest                                                     # 245 passed
ruff check src tests gateway scripts                       # clean
mypy src/device_control gateway/src/device_gateway         # 42 files clean
bandit -c .bandit -r src gateway/src                       # no issues
pip-audit -r requirements/audit.txt                        # no known vulnerabilities
OpenAPI                                                    # no drift
```

MindOS:

```
pytest ../../tests ../../packages/contracts/tests            # 627 passed, 1 skipped
ruff check apps/api-gateway                                  # clean
mypy apps/api-gateway/app                                    # 746 files clean
pytest --collect-only                                        # 2336 collected
pytest packages/contracts/tests tests/contracts              # 291 passed
architecture / convergence / inventory / validation          # PASS
source truth / source release                                # PASS
```

## Conclusion

Security gate findings and owner-lease epoch bugs are fixed locally. Durable
state is available as a TaskRun projection, but the canonical TaskRun call site
is still absent; therefore the real integration and live E2E gates remain
BLOCKED. Overall **NO-GO**; production physical writes stay OFF.
