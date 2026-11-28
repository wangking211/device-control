# DC-014-CLOSE-01 CI Gate Reproduction

Date: 2026-11-28
Remote CI/Evidence runs `46120415192` and `46120416223` are referenced in the
task pack, but this environment has no `gh` CLI or GitHub token. Their job/step
logs and annotations are an explicit **evidence gap**; no root cause is guessed.

Local reproduction of the named Evidence Gate jobs:

| Gate | Local command | Result |
|---|---|---|
| Component Inventory | `python scripts/ci_inventory.py --check --output reports/ci-inventory.json` | PASS (written) |
| Security Gate | `python scripts/validation_policy_check.py` | PASS |
| Architecture Guard | `python scripts/architecture_guard.py --strict --format=json` | PASS |
| Agent backend docs | `python scripts/check_agent_backend_arch_docs.py` | PASS |
| Registry source truth | `python scripts/registry_source_truth_check.py` | PASS |
| Authority consistency | `python scripts/authority_consistency_check.py` | PASS |
| Layer dependency | `python scripts/layer_dependency_check.py` | PASS |
| Route inventory | `python scripts/route_inventory.py --check` | PASS |
| Runtime registry access | `python scripts/runtime_registry_access.py` | PASS |
| Source migration / SDK boundary | baseline scripts | PASS |
| Python Quality lint | `python -m ruff check apps/api-gateway` | PASS after fixes |
| API modularization | `python scripts/api_modularization_gate.py` | PASS |
| Python Quality type | `mypy apps/api-gateway/app` | PASS (746 files; full-dir run polluted by local `data/` checkouts) |
| Clean Clone collect | `python -m pytest -q --collect-only` | 2328 collected |
| Contract smoke | `python -m pytest -q packages/contracts/tests tests/contracts` | 291 passed |
| Python service tests | `pytest ../../tests ../../packages/contracts/tests` | 619 passed, 1 skipped |

## Reproduced root causes fixed

1. **Ruff F401/F841**: router composition modules import handlers for FastAPI
   registration; removing them would drop routes. Scoped per-file ignores were
   added for those four registration modules. Real unused imports/locals were
   removed in app/tests.
2. **Clean Clone collect**: `agent_node_test_client`, worker helper modules and
   `skillseekers_capability_policy` were not importable from the root pytest
   configuration. Added the canonical source/test roots. Generated `data/`,
   release-context copies and a manual collaboration script are not collected.
3. **Local-only boundary failures**: `release-context/**` is untracked generated
   output; a clean clone does not contain it. No checker was weakened.

## Still blocked

- Remote CI / Evidence Gates URLs and annotations.
- `Release Evidence` job (not executed locally; `generate_release_evidence.py`
  can be run, but the remote artifact cannot be verified here).
- Container smoke and Docker jobs.
