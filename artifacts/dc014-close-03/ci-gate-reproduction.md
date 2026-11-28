# DC-014-CLOSE-03 CI Gate Reproduction

Remote CI `46132730981` and Evidence Gates `46132731983` cannot be inspected:
the GitHub connector returned job summaries but log retrieval returned
NOT_FOUND, and this environment has no `gh` CLI or token. That is an explicit
evidence gap; no failure cause is invented.

Local source-line reproduction:

| Check | Command | Result |
|---|---|---|
| Ruff | `python -m ruff check apps/api-gateway` | PASS |
| mypy | `mypy apps/api-gateway/app` | PASS (746 files) |
| Clean clone collect | `python -m pytest -q --collect-only` | 2336 collected |
| Contract smoke | `pytest packages/contracts/tests tests/contracts` | 291 passed |
| API/package tests | `pytest ../../tests ../../packages/contracts/tests` | 627 passed, 1 skipped |
| Architecture Guard | `python scripts/architecture_guard.py --strict` | PASSED |
| Convergence | `python scripts/repository_convergence_check.py` | PASS |
| Component Inventory | `python scripts/ci_inventory.py --check ...` | PASS |
| Security Gate | `python scripts/validation_policy_check.py` | PASS |
| Source truth/release | generator `--check`, `source_release_check` | PASS |

Release Evidence is not produced/uploaded here. Container smoke, Docker and
Release Evidence artifacts remain BLOCKED without Docker/GitHub access.
