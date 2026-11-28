# DC-014-CLOSE-02 CI Gate Reproduction

Remote runs `46129214242` (CI) and `46129215362` (Evidence Gates) cannot be
inspected: this environment has no `gh` CLI and no GitHub token. The jobs
endpoint returned zero jobs; that is recorded as an evidence gap. No root cause
is inferred from check names.

Local reproduction on the same source line:

| Check | Command | Result |
|---|---|---|
| Ruff | `python -m ruff check apps/api-gateway` | PASS |
| API boundaries | `python scripts/api_modularization_gate.py` | PASS |
| mypy | `mypy apps/api-gateway/app` | PASS (746 files) |
| Clean Clone collect | `python -m pytest -q --collect-only` | 2333 collected |
| Contract smoke | `pytest packages/contracts/tests tests/contracts` | 291 passed |
| Component Inventory | `python scripts/ci_inventory.py --check ...` | PASS |
| Security Gate | `python scripts/validation_policy_check.py` | PASS |
| Architecture Guard | `python scripts/architecture_guard.py --strict` | PASS |
| Convergence | `python scripts/repository_convergence_check.py` | PASS |
| Source truth / release | generator `--check`, `source_release_check` | PASS |

Release Evidence itself was not produced/uploaded here; the remote artifact is
still required. Docker/container smoke is BLOCKED (no Docker daemon).
