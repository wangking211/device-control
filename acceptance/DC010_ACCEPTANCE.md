# DC-010 Acceptance Matrix

Status: PASS / FAIL / BLOCKED / PARTIAL. PASS requires a command/environment.
This run: Windows, Python 3.12.9, pytest 9.1.1, no adb/emulator/device, no Docker
daemon, no live MindOS API. Automated result: **102 passed**, Ruff/mypy clean,
Bandit 0 issues (only `B101` skipped), pip-audit no known vulnerabilities.

| ID | Requirement | Priority | Status | Evidence |
|---|---|---:|---|---|
| A-001 | No unverified redaction upload | P0 | PASS | Server requires HMAC proof for screenshot/node_summary; `tests/test_evidence.py` |
| A-002 | Sensitive regions irreversibly masked | P0 | PASS | `gateway/tests/test_redaction.py` masks status bar and sensitive node bounds; pixel assertions |
| A-003 | Redaction proof tamper/replay rejected | P0 | PASS | `test_tampered_proof...`, `test_evidence_rejects_hash_mismatch_unredacted_and_bad_type` |
| A-004 | Gateway independently derives policy | P0 | PASS | `preflight` derives allow/ask from manifest risk; `test_upstream_policy_allow_cannot_authorize_a_write` |
| A-005 | Approval binds tenant/device/op/params/state/manifest/policy | P0 | PASS | `test_approval_binds_parameters_version_state_and_device`, canonical digest tests |
| A-006 | Nonce atomic single use | P0 | PASS | `test_concurrent_approval_consumption_succeeds_at_most_once` |
| A-007 | Fingerprint/state missing/stale/future rejected | P0 | PASS | `test_state_missing_or_stale_is_rejected`, `test_state_dependent_capability_requires_hash_and_version` |
| A-008 | Production requires signed manifest | P0 | PASS (unit) | `test_ed25519_manifest_signature_and_key_id`, gateway startup validation |
| A-009 | Ed25519 rotation/revocation | P0 | PARTIAL | key id/allowed set + revision/runbook; live rotation not executed |
| A-010 | Docker Gateway profile starts/heartbeats | P0 | BLOCKED | Docker daemon unavailable; compose/config conflict fixed with explicit dev flag |
| A-011 | Production TLS/mTLS | P0 | BLOCKED | No ingress/certificates; HTTPS enforcement + config tests only |
| A-012 | OpenAPI deterministic/drift clean | P0 | PASS (local) | `scripts/export_openapi.py`, `tests/test_openapi.py`, constraints pins; remote CI not run |
| A-013 | Evidence storage replaceable | P1 | PARTIAL | `evidence.get_object_store` + foundation-storage adapter; local backend tested, foundation/S3 not executed |
| A-014 | Backup/restore DB+Evidence integrity | P1 | PASS (local) | `tests/test_operations.py`, `restore_sqlite.py` dry-run |
| A-015 | MindOS Provider real registration | P1 | PARTIAL | `mind-os/edge-agent/connectors/device_control_provider.py` + descriptor/contract tests; live registry BLOCKED |
| A-016 | TaskRun ↔ command traceability | P1 | PARTIAL | Device Control refs/tests; live MindOS TaskRun BLOCKED |
| A-017 | Approval UX blocks execution before approval | P1 | PASS (device-control) / BLOCKED (MindOS UI) | control plane 409/approval tests |
| A-018 | Cancel/timeout/retry/idempotency E2E | P1 | PASS (device-control) / BLOCKED (live MindOS) | command tests |
| A-019 | Android real-device E2E | P1 | BLOCKED | No adb/device/emulator |
| A-020 | `executed_unverified` never success | P0 | PASS | `test_executed_unverified_is_not_success`, worker mapping |
| A-021 | Restore drill/runbook | P1 | PARTIAL | automated dry-run PASS; manual RPO/RTO drill BLOCKED |
| A-022 | CI all green, no scanner exemptions | P0 | PARTIAL | local 102 tests + scanners clean; remote CI not executed |

## Gate decision

**NO-GO** until A-010, A-011, A-019 and live MindOS/Android/E2E + restore drill
rows are executed with real evidence. Structural redaction is verified, but real
device screenshots remain BLOCKED and must not be claimed as PASS.
