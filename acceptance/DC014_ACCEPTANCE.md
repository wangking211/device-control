# DC-014 Acceptance

Date: 2026-11-28
Device Control: `main` after this change set (see commit log)
MindOS: `main` after this change set (see commit log)

Status vocabulary: PASS (local evidence), PARTIAL (local evidence but a
required environment is missing), BLOCKED (environment absent; not PASS).

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| D14-000 | Latest baseline and CI | PARTIAL | `docs/DC014_BASELINE.md`; real SHAs recorded; local CI-equivalent run green; remote CI logs/checks unavailable (no `gh`/token) |
| D14-001 | Missing device binding rejected | PASS | `tests/test_ha_binding_negative.py`: missing/forged tenant, gateway, platform, endpoint, device; revoked/expired/revision-stale; zero HA POST |
| D14-002 | Status contract consistent | PASS | `tests/test_command_state_contract.py` and `mind-os/tests/test_device_control_provider_dc014.py`; identical mapping on both sides |
| D14-003 | Existing Registry resolves provider | PARTIAL | `tests/test_device_control_provider_dc014.py` resolves the catalog entry through `RuntimeAuthorityResolver`; live health probe BLOCKED |
| D14-004 | Real TaskRun submit/get/cancel/evidence | BLOCKED | No running MindOS+Device Control; local lifecycle tests in `mind-os/tests/test_device_task_run_dc014.py` only |
| D14-005 | Approval denial has zero side effects | PARTIAL | Synthetic worker tests assert no HA POST for missing/denied approval; live HA state proof BLOCKED |
| D14-006 | WS durable ingestion | PARTIAL | `tests/test_ha_ingest.py`: persisted event/cursor/telemetry/twin, dedupe; live HA stream BLOCKED |
| D14-007 | Reconnect reconciliation | PARTIAL | Synthetic reconnect records gap marker, runs REST read-back, restores final state; real restart/gap drill BLOCKED |
| D14-008 | Telemetry/Twin convergence | PASS | Duplicate, attribute-only, late/out-of-order, future-skew and per-device freshness tests |
| D14-009 | Claim/authorize/revoke UI | BLOCKED | No browser/frontend runtime here; API claim/read-only already tested |
| D14-010 | Docker + HA E2E | BLOCKED | No Docker daemon; compose file present, not executed |
| D14-011 | Android controlled E2E | BLOCKED | No emulator/device |
| D14-012 | Production secrets/backup drill | BLOCKED | No production environment; write features remain disabled |
| D14-013 | Cross-tenant rejection | PASS | Platform/device/ingest/command tests return 404/empty for another tenant |

## Local commands used

Device Control:

```
python -m pytest -q                     # 190 passed
ruff check src tests gateway            # clean
bandit -r src/device_control             # no issues identified
```

MindOS (from `apps/api-gateway`):

```
python -m pytest -q ../../tests ../../packages/contracts/tests   # 609 passed, 1 skipped
python scripts/architecture_guard.py --strict                    # PASSED
python scripts/repository_convergence_check.py                   # PASS
python scripts/source_release_check.py --check --tracked-only    # PASS
python scripts/generate_source_truth.py --check                  # PASS after regeneration
```

## Overall

**NO-GO for production / real device writes.** P0 local code gates are green,
but live HA, live MindOS TaskRun, Docker E2E, Android and production recovery
drills are BLOCKED. Real writes must remain disabled until those are executed
and recorded with sanitized evidence.
