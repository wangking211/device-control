# Acceptance Matrix — DC-002 … DC-005

Environment for this run (2026-11-26):

- Windows, Python 3.12.9, pytest 9.1.1, FastAPI 0.116.1, jsonschema 4.26.0
- No `adb` on PATH, no Android emulator/device, no Docker daemon
- Command: `python -m pytest -q` from `products/device-control`
- Result: **87 passed** (control-plane + gateway/adapter + evidence/ops tests)
  - `python -m ruff check ...` → pass
  - `python -m mypy src/device_control gateway/src/device_gateway` → pass
  - `bandit -c .bandit -r src gateway/src` → 0 issues, only `B101` globally skipped
  - `pip-audit -r requirements/audit.txt` → no known vulnerabilities

Legend: PASS = executed here; BLOCKED = requires hardware/runtime not present;
N/A = not applicable to this product.

## DC-002 Security

| Criterion | Result | Evidence |
| --- | --- | --- |
| Forged approver identity rejected | PASS | `test_forged_approver_identity_is_ignored_and_signature_is_verified` — body `approver_ref` ignored; stored approver is the verified principal; bad signature → 401 |
| Cross-tenant access denied | PASS | `test_cross_tenant_access_is_hidden` — 404 for detail/decision, empty lists |
| Expired/released lease blocks approval consumption | PASS | `test_released_lease_blocks_approval_consumption` — 409 and approval `invalidated` |
| Revoked/offline endpoint invalidates approval and queued commands | PASS | `test_revoked_endpoint_invalidates_approval_and_queued_commands` |
| Approval binds exact action, capability version and state hash | PASS | `test_approval_binds_parameters_version_and_state_hash` — `approval_binding_mismatch` |
| Concurrent consumption succeeds at most once | PASS | `test_concurrent_approval_consumption_succeeds_at_most_once` — statuses `[201, 409]` |
| Production mode rejects bootstrap token | PASS | `test_production_rejects_bootstrap_token` |
| Secrets absent from logs/responses | PASS | `test_secrets_are_absent_from_responses_and_logs` (credential, enrollment token, `credential_hash`) |
| Migration preserves existing records | PASS | `test_versioned_migration_preserves_legacy_records` — legacy endpoint/lease/approval retained |
| Non-root Docker process writes to persistent `/data` volume | **BLOCKED** | `Dockerfile` configures UID 10001, `/data`, `VOLUME`; Docker is unavailable here so the container was not built/run |
| Payload limit / rate limit / expired token / issuer pin | PASS | `test_payload_limit_rejects_oversize_body`, `test_expired_token_and_issuer_mismatch_rejected`; rate limiter is covered indirectly (429 path) |
| Service token shape / audience / actor binding | PASS | `test_service_token_shape_and_audience_are_verified` — capability scope, audience pin, impersonating actor rejected |

## DC-003 Gateway

| Criterion | Result | Evidence |
| --- | --- | --- |
| Enrollment and credential rotation | PASS | `test_gateway_enrollment_activation_and_rotation` — replay 401, old credential 401 after rotation |
| Gateway identity distinct from endpoint | PASS | `test_gateway_and_endpoint_credentials_are_not_interchangeable` |
| Heartbeat and stale/offline transition | PASS | `test_stale_gateway_transitions_offline_and_emits_event` |
| Wrong tenant/gateway delivery denied | PASS | `test_cross_gateway_and_cross_tenant_delivery_denied` |
| Backpressure and bounded queue | PASS | `gateway/tests/test_ledger_queue.py`, `test_backpressure_rejects_second_command` |
| Revocation invalidates leases and pending work | PASS | `test_gateway_revocation_invalidates_endpoint_work` |
| Reconnect reconciles command state | PASS | `test_ledger_dedupes_conflicts_and_survives_reopen`, `test_duplicate_uncertain_non_idempotent_is_not_reexecuted`, `test_timeout_and_late_result_are_reconciled_without_reopening` |
| Adapter crash isolated from control plane | PASS | `test_adapter_crash_and_timeout_become_uncertain` |
| Pull before heartbeat refused | PASS | `test_gateway_action_requires_online_heartbeat` (409 `gateway_not_online`) |
| TLS/mTLS termination and secret distribution | **BLOCKED** | Deployment concern; no ingress/certificate environment here |
| Multi-instance rate limiting | **BLOCKED** | Process-local limiter; SQLite single-writer; documented limitation |

## DC-004 Android

| Criterion | Result | Evidence |
| --- | --- | --- |
| Emulator discovery and screenshot | **BLOCKED** | No Android SDK/emulator. Adapter logic tested with a stubbed adb binary: `test_adb_parses_foreground_app_and_hashes_screenshots` |
| Real Android USB pairing and heartbeat | **BLOCKED** | No `adb`/device attached |
| Wi-Fi pairing where supported | **BLOCKED** | No device |
| Allowlisted app launch and harmless UI action | PASS (fake adapter, full loop) / **BLOCKED** (real device) | `test_end_to_end_fake_android_loop`; real-device procedure in `docs/DC-004-ANDROID-GATEWAY.md` |
| Action result verified | PASS (fake) | `test_end_to_end_fake_android_loop` — `verification.method=ui_state`, command `succeeded` |
| Screen change invalidates approval | PASS | `test_changed_state_is_rejected_before_execution`; preflight `state_changed` |
| User takeover pauses | PASS | `test_user_takeover_pauses_and_disconnect_is_uncertain` — local pause + rejected `user_takeover` |
| Disconnect mid-command produces uncertain/failed | PASS (fake) | same test — command `uncertain` |
| Secret fields/prohibited apps blocked | PASS | `test_adb_refuses_non_allowlisted_apps_and_unsafe_text`, `test_adb_rejects_secret_fields_without_calling_device`, `test_secret_fields_allowlist_and_state_hash_are_enforced` |
| Screenshot redaction and retention | PASS (adapter contract) | screenshot hashed and discarded; `evidence_refs=[sha256:...]`; raw frame never leaves the adapter |
| ADB injection safety/timeouts/output caps | PASS | `test_adb_invocation_uses_argument_arrays_and_no_shell`, `test_adb_timeout_is_uncertain`, bounded capture in adapter |

Emulator-only is not real-device acceptance; DC-004 remains **not accepted** for
production until the real-device rows pass.

## DC-005 Command

| Criterion | Result | Evidence |
| --- | --- | --- |
| State transitions audited | PASS | `test_full_command_state_machine_is_audited` — created→…→succeeded, transitions + events |
| Same idempotency key/same payload returns existing | PASS | `test_idempotency_same_payload_returns_existing_and_conflict_is_409` (`deduplicated: true`) |
| Same key/different payload returns 409 | PASS | same test (`idempotency_conflict`) |
| No blind retry for uncertain non-idempotent action | PASS | `test_duplicate_uncertain_non_idempotent_is_not_reexecuted` |
| Timeout/cancel/late result reconciled | PASS | `test_cancel_before_dispatch_and_refusal_after`, `test_timeout_and_late_result_are_reconciled_without_reopening`, `test_gateway_pull_expires_overdue_commands` |
| Succeeded requires verification | PASS | `test_succeeded_requires_verification`, `test_adapter_ack_without_guarantee_is_not_success` |
| MindOS TaskRun links command and evidence | PASS (contract level) / **BLOCKED** (live MindOS) | `task_ref`/`run_ref`/`correlation_id` persisted and emitted; `GET /v1/commands/{id}/evidence`; `examples/mindos_client.py` |
| MindOS non-device features work when Device Control is down | **BLOCKED** | Requires a running MindOS deployment; design documented in `docs/MINDOS-INTEGRATION.md` |
| E2E harmless Android scenario passes | PASS (fake adapter in-process) / **BLOCKED** (real Android + MindOS) | `test_end_to_end_fake_android_loop`, `test_user_takeover_pauses_and_disconnect_is_uncertain` |
| Negative tests: offline, wrong tenant, expired lease, missing approval, changed state, adapter crash | PASS | `test_submission_negative_paths`, `test_offline_endpoint_blocks_command`, `test_changed_state_is_rejected_before_execution`, `test_adapter_crash_and_timeout_become_uncertain` |

## DC-006 Security execution (release blocker)

| Criterion | Result | Evidence |
| --- | --- | --- |
| Manifest risk/operation authoritative; envelope downgrade rejected | PASS | `test_manifest_digest_operation_and_risk_cannot_be_downgraded`, `test_manifest_risk_is_authoritative_even_if_envelope_downgrades` |
| Manifest missing/tampered/signature/digest rejected | PASS | `test_manifest_signature_is_required_when_configured`, `test_manifest_digest_drift_blocks_dispatch` |
| Parameters schema validated | PASS | `test_typed_parameters_are_validated` |
| Approval binds operation/device/endpoint/parameters/state/policy/nonce | PASS | `test_approval_binds_parameters_version_state_and_device`, `test_concurrent_approval_consumption_succeeds_at_most_once` |
| Endpoint↔device fingerprint binding | PASS (automated) / **BLOCKED** (real swap) | `test_endpoint_device_fingerprint_binding`; real device swap needs hardware |
| State hash/version missing/stale/changed rejected | PASS | `test_state_dependent_capability_requires_hash_and_version`, `test_state_missing_or_stale_is_rejected`, `test_changed_state_is_rejected_before_execution` |
| Caller labels cannot bypass sensitive control detection | PASS | `test_secret_fields_allowlist_and_state_are_enforced`, `test_adb_rejects_password_control_and_does_not_type` |
| Secrets absent from logs/results/evidence | PASS | `test_typed_text_is_not_echoed_in_result_or_evidence`, `test_secrets_are_absent_from_responses_and_logs` |
| Adapter hard timeout/kill/rebuild; uncertain non-idempotent not replayed | PASS (fake adapter) | `gateway/tests/test_isolation.py`, `test_duplicate_uncertain_non_idempotent_is_not_reexecuted` |
| tap/type/screenshot verification failure not success | PASS | `test_executed_unverified_is_not_success`, `test_succeeded_requires_verification`, adapter `executed_unverified` paths |
| Bandit config parse/failure blocking/dependency audit | PASS | `tests/test_ci_security.py`; Bandit 1.9.4 clean with only `B101` skipped; `pip-audit -r requirements/audit.txt` no findings |

## DC-007 Android/Evidence

| Criterion | Result | Evidence |
| --- | --- | --- |
| Structured discovery (device/unauthorized/offline) | PASS (stub) / **BLOCKED** (real) | `test_discovery_reports_unauthorized_and_offline` |
| Accessibility node summary, redacted | PASS (stub) | `test_adb_parses_ui_nodes_and_hashes_screenshots`; text never exposed |
| Real device full loop | **BLOCKED** | No adb/emulator/device; run `docs/android/ANDROID_SETUP_AND_RUNBOOK.md` |
| Evidence metadata + object bytes + hash + retention + access | PASS (local store) | `tests/test_evidence.py`, `gateway/tests/test_worker_e2e.py::test_screenshot_artifact_uploads_evidence` |
| Real Evidence object storage/durability | **BLOCKED** | Local FS adapter only; production object store required |
| Disconnect/restart/replug reconcile, no replay | PASS (fake) / **BLOCKED** (real) | `test_user_takeover_pauses_and_disconnect_is_uncertain`, command timeout/late-result tests |
| Manual pause/resume | PASS (gateway local) | worker pause/resume test; no cloud round-trip |
| Diagnostics | PASS | `test_gateway_diagnostics_exposes_health_without_secrets`, `/v1/alerts` |

## DC-008 MindOS/contract governance

| Criterion | Result | Evidence |
| --- | --- | --- |
| Contract mapping documented | PASS | `docs/contracts/MINDOS_DEVICE_INTENT_MAPPING.md` |
| OpenAPI 3.x exported | PASS | `contracts/openapi-v1.json`, `tests/test_openapi.py`, CI drift check |
| Provider with auth/timeout/retry/idempotency/error mapping/trace | PASS | `examples/mindos_provider.py`, `tests/test_mindos_contract.py` |
| Live MindOS API call + TaskRun E2E | **BLOCKED** | No MindOS runtime; MindOS tree dirty; consumer contract tests delivered |
| Cross-tenant/actor spoof rejection | PASS | `test_provider_rejects_cross_tenant_and_actor_spoofing` |
| Uncertain non-idempotent not auto-retried | PASS | provider retry policy + command tests |

## DC-009 Production operations

| Criterion | Result | Evidence |
| --- | --- | --- |
| Docker repeatable start/persistence/backup | **BLOCKED** | No Docker daemon; Dockerfile/compose/backup script delivered |
| Backup/restore integrity tooling | PASS (local) | `tests/test_operations.py::test_sqlite_backup_and_integrity_manifest` |
| TLS/mTLS + credential lifecycle | PARTIAL / **BLOCKED** (mTLS run) | HTTPS enforcement middleware; rotation/revocation tests; no ingress here |
| Gateway preflight + signed upgrade | PASS (tooling) | `test_gateway_preflight_blocks_insecure_transport`, `test_signed_upgrade_is_verified_or_rejected` |
| Device management API/UI | PASS (static shell) | `/admin` test; APIs listed in `docs/API.md` |
| Monitoring/alerts/audit | PASS | `/v1/metrics`, `/v1/alerts`, diagnostics, audit tests |
| Tenant isolation | PASS | `test_cross_tenant_access_is_hidden` and evidence tenant tests |

## Conclusion

- DC-006: automated security gates **PASS**; real-device safety remains BLOCKED.
- DC-007: evidence/observation/diagnostics code and fake-adapter loop PASS; real
  Android and durable object storage BLOCKED.
- DC-008: OpenAPI/mapping/provider contract tests PASS; live MindOS E2E BLOCKED.
- DC-009: scripts/HTTPS/admin/alerts PASS locally; Docker/TLS/mTLS acceptance
  BLOCKED.

Overall release decision: **NO-GO** until every BLOCKED row is executed on real
hardware/Docker/MindOS and recorded here. Closing scanners or using the fake
adapter is not accepted as PASS for Gate B.
