# DC-014-CLOSE Reproduction

All commands were run from the repository roots on 2026-11-28 (Windows,
Python 3.12).

## Device Control

```powershell
cd products/device-control
python -m pytest -q
ruff check src tests gateway
mypy src/device_control gateway/src/device_gateway --ignore-missing-imports --no-site-packages
bandit -c .bandit -r src gateway/src
pip-audit -r requirements/audit.txt
python scripts/export_openapi.py
git diff --exit-code contracts/openapi-v1.json
```

New/updated suites:

```powershell
python -m pytest tests/test_binding_document.py tests/test_ha_binding_negative.py -q
python -m pytest tests/test_lease_matrix.py -q
python -m pytest tests/test_provider_contract.py -q
python -m pytest tests/test_ha_ingest.py tests/test_production_gate.py -q
```

## MindOS

```powershell
cd products/mind-os/apps/api-gateway
python -m pytest -q ../../tests ../../packages/contracts/tests

cd ../..
python scripts/architecture_guard.py --strict
python scripts/repository_convergence_check.py
python scripts/source_release_check.py --check --tracked-only
python scripts/generate_source_truth.py --check
```

Device provider suites:

```powershell
python -m pytest tests/test_device_control_provider_dc010.py `
  tests/test_device_control_provider_dc014.py `
  tests/test_device_task_run_dc014.py -q
```

## Blocked reproductions

```text
docker version   -> command not found
docker compose   -> command not found
adb devices      -> command not found
gh run list      -> command not found
```

Therefore Docker + HA E2E, Android E2E and remote CI log retrieval are
**BLOCKED**; no mock result is reported as a live PASS.
