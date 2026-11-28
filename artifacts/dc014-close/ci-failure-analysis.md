# DC-014-CLOSE CI Failure Analysis

## Evidence gap (explicit)

`gh` CLI is not installed and neither `GITHUB_TOKEN` nor `GH_TOKEN` is set in
this environment. GitHub Actions history, job/step logs and check status cannot
be fetched. The remote CI conclusion is **BLOCKED**, not PASS. This document
records only failures that were reproduced locally.

## Reproduced failures at the DC-014 baseline

| # | Symptom | Class | Root cause | Fix |
|---|---|---|---|---|
| 1 | `ModuleNotFoundError: connectors` in `tests/test_device_control_provider_dc010.py` | Code / test bootstrap | `conftest.py` added `apps/edge-agent/src` but not the top-level `edge-agent` package used by the device connector tests | Added `edge-agent` to `PACKAGE_PATHS` |
| 2 | `global navigation is not frozen to four entries` | Code / stale assertion | Checker froze the pre-UI-001 menu while `menu-registry.ts` had already moved to `chat/work/knowledge/assistants/spaces` | Checker now mirrors the registry invariant; assertion not removed |
| 3 | Source-release violations on `.tar.gz` and Playwright `.last-run.json` | Hygiene | Binary/test artifacts were tracked in source | Removed from tracking (history retained) |
| 4 | Repository convergence: canonical script imports legacy | Code / layout | Three retired `baseline_024_*` shims still lived in `scripts/` | Moved under `scripts/legacy/` |

After these fixes the local CI-equivalent suite is green:

```
cd apps/api-gateway
python -m pytest -q ../../tests ../../packages/contracts/tests
# 610 passed, 1 skipped
```

## Dedicated DC-014 checks

Device Control and the MindOS provider contract tests were added/updated for
binding revision, signed binding documents, read/write lease separation and
provider payload conformance. They pass locally; see `reproduction.md`.

## What is still unproven

- The new remote workflow runs and required checks.
- Docker/container jobs (no Docker daemon).
- HA and Android live E2E (no instance/device).

If remote logs later show a different failure, it must be classified with the
actual job/step log; no guess is recorded here as fact.
