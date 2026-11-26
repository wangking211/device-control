# Device Execution Threat Model (DC-006)

## Assets

Device actions and their physical consequences; user screen content; approval
decisions; gateway/endpoint credentials; command/evidence metadata; tenant
isolation; audit trail.

## Trust boundaries

1. **Caller → control plane.** Only verified platform principals. Tenant,
   requester, approver and lease holder come from claims. The bootstrap token
   is local provisioning only and rejected in production.
2. **Control plane → gateway.** Gateway credential over TLS/mTLS. The envelope
   is *not* trusted for risk, operation, device identity or success.
3. **Gateway → adapter/device.** Trusted local manifest is authoritative. ADB is
   an argument array with fixed executable, restricted environment, timeout and
   bounded output. The adapter runs in a killable child process.
4. **Evidence storage.** Control plane owns metadata and access checks; bytes
   live in object storage. No raw screen content in SQLite, logs or events.

## Threats and controls

| Threat | Control | Test |
| --- | --- | --- |
| Upstream downgrades `risk_tier` | Gateway uses manifest risk and rejects mismatch | `test_manifest_digest_operation_and_risk_cannot_be_downgraded`, `test_manifest_risk_is_authoritative_even_if_envelope_downgrades` |
| Manifest missing/tampered/wrong version | Signature when configured, digest pin, revision history, dispatch blocked on drift | `test_manifest_signature_is_required_when_configured`, `test_manifest_digest_drift_blocks_dispatch` |
| Unknown capability/operation/parameters | Manifest capability lookup + JSON Schema validation | `test_manifest_rejects_unknown_...`, `test_typed_parameters_are_validated` |
| Approval replay | One-time nonce + atomic `consumed` transition + exact binding | `test_concurrent_approval_consumption_succeeds_at_most_once`, `test_approval_binds_parameters_version_state_and_device` |
| Device swap / endpoint mix-up | Endpoint↔device fingerprint binding, gateway local endpoint id check, manifest pin | `test_endpoint_device_fingerprint_binding`, `test_binding_deadline_and_endpoint_are_enforced` |
| Stale/changed UI state | State hash+version and max age; re-observe immediately before execution | `test_state_missing_or_stale_is_rejected`, `test_changed_state_is_rejected_before_execution` |
| Caller hides a sensitive field | Node-derived `password`/editable/resource-id checks; caller `target_type` only adds a deny | `test_secret_fields_allowlist_and_state_are_enforced`, `test_adb_rejects_password_control_and_does_not_type` |
| Weak/absent verification | Capability manifest verification type; `executed_unverified` never maps to success | `test_succeeded_requires_verification`, `test_executed_unverified_is_not_success` |
| Adapter hang | Child-process hard timeout, terminate/kill, rebuild; uncertain replay ban | `gateway/tests/test_isolation.py` |
| Duplicate delivery after crash | Durable gateway ledger; non-idempotent duplicates become uncertain | `test_duplicate_uncertain_non_idempotent_is_not_reexecuted` |
| Evidence tamper | SHA-256 on upload and download; size/type/redaction checks; tenant-scoped access; access audit | `tests/test_evidence.py` |
| SQL injection | Bound parameters; dynamic fragments are fixed clauses/`?` placeholders | Bandit clean with targeted `# nosec B608` justifications |
| Secret leakage | No credential/body logging; no raw screen text in node summaries; sensitive controls rejected before typing | `test_secrets_are_absent_from_responses_and_logs`, `test_typed_text_is_not_echoed_in_result_or_evidence` |
| Scanner bypass | Bandit config has only `B101` skipped; CI fails on findings and then runs dependency audit | `tests/test_ci_security.py` |

## Residual risks / limits

- A compromised gateway host is inside the trust boundary for the attached
  device; it can execute manifest-declared capabilities.
- WebView/Canvas and permission-restricted Accessibility trees may produce
  `quality=low`; state-bound actions fail closed when the target cannot be
  identified.
- SQLite is single-writer; process-local rate limiting.
- Real hardware and Docker acceptance are blocked in this environment.
