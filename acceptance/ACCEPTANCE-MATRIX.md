# Acceptance Matrix — DC-002 … DC-005

Environment for this run (2026-11-26):

- Windows, Python 3.12.9, pytest 9.1.1, FastAPI 0.116.1, jsonschema 4.26.0
- No `adb` on PATH, no Android emulator/device, no Docker daemon
- Command: `python -m pytest -q` from `products/device-control`
- Result: **57 passed** (35 control-plane tests + 22 gateway/adapter tests)
  - `python -m ruff check src tests gateway/src gateway/tests scripts` → pass
  - `python -m mypy src/device_control gateway/src/device_gateway --ignore-missing-imports` → pass

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

## Conclusion

- DC-002: code and automated acceptance **PASS**; Docker persistence **BLOCKED**.
- DC-003: protocol and lifecycle **PASS**; TLS/mTLS/multi-instance **BLOCKED**.
- DC-004: adapter/worker **PASS** with fake adapter; real Android **BLOCKED**.
- DC-005: state machine/idempotency/verification/events **PASS**; live MindOS
  TaskRun correlation and real-device E2E **BLOCKED**.

Do not declare production-ready until every BLOCKED row has command output,
environment details and (for devices) redacted evidence recorded here.
