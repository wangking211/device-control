# BASELINE AUDIT — DC-006…DC-009

Date: 2026-11-26. Baseline task pack expects `device-control` `cb13f8b`.

| Repo | Local HEAD | origin/main | Working tree |
| --- | --- | --- | --- |
| `device-control` | `cb13f8b1e64ad60077191ec47653f57f545b180f` | same | clean |
| `ai-platform` | `2846bf0179e5dff5ab33892b431bd666e305657f` | `aa08cea57e7c332aa1bb53b4c8ccbe5f95c0c4bd` | pre-existing dirty tree; not modified in this phase |
| `mind-os` | `93af90c5d8edeb19586eefea3b4f91e401080279` | same | pre-existing dirty tree; not modified in this phase |

`ai-platform` is behind its remote main by `2846bf01..aa08cea5`. Pulling it
would mix unrelated dirty changes into this task, so no rebase/pull was done;
the remote SHA is recorded for contract review only.

## DC-006 — Security execution and UI semantics

| # | Requirement | Status | Current location | Gap / minimal fix |
| --- | --- | --- | --- | --- |
| 1 | Capability risk only from trusted, versioned local Manifest; envelope risk consistency-checked | **Partial, unsafe** | `gateway/src/device_gateway/preflight.py`, `manifest.py`, `gateway/src/device_gateway/worker.py` | Preflight trusts `command["risk_tier"]` for denial and never compares it to manifest risk. Control plane uses endpoint-reported capability risk (`app.submit_command`) which is untrusted. Fix: signed/digested manifest registered per gateway, manifest risk authoritative, envelope risk/operation/digest mismatches rejected, dispatch blocked on digest drift. |
| 2 | Approval binds operation, device, endpoint, capability/version, canonical parameters, state version/hash, policy, requester/approver, expiry, one-time nonce | **Partial** | `src/device_control/canonical.py`, `store.py`, `app.py` | Binds tenant/endpoint/gateway/capability/version/parameters/intent/requester/lease/policy/state hash. Missing operation, device id/fingerprint, state version, nonce, manifest digest. Single-use atomic consumption already works. |
| 3 | One gateway = one Android device; endpoint physically bound; serial only local config | **Missing** | `store.enroll_endpoint`, gateway config | No `device_id`/fingerprint columns, no local endpoint binding in gateway, envelope can target any endpoint of the gateway. Fix: endpoint fingerprint, gateway config endpoint/device/fingerprint, preflight identity check, repairable re-pairing. |
| 4 | Rich state observation; low-trust foreground not enough; state freshness/version | **Partial** | `android_adb.py`, `fake.py`, `worker.py` | Only foreground/screen + hash. No accessibility summary, source/quality/observed_at/version, no max state age. Fix: UIAutomator node summaries, state version, freshness window, control-plane approval/command binding. |
| 5 | Sensitive controls derived from Accessibility, not caller labels | **Partial, unsafe** | `policy.py`, `android_adb.py` | Caller `target_type` and app markers only. Fix: resolve target node from UI tree; password/editable/inputType/resourceId checks; fail closed when unknown; caller label is only an additional deny hint. |
| 6 | Executed vs verified; capability postconditions; no false `succeeded` | **Partial** | `commands.py`, `worker.py`, adapters | Verification is any `verified=true` object; tap may be unchanged; `succeeded` can be claimed with a weak `ui_state`. No `executed_unverified`. Fix: capability success criteria, adapter post-state verification, new terminal `executed_unverified`, stronger checks for tap/type/screenshot. |
| 7 | Isolated adapter process with hard timeout, terminate/rebuild, uncertain replay ban | **Partial** | `android_adb.py`, `worker.py`, `ledger.py` | `adb` subprocess has a timeout, but adapter logic runs in-process; a hung adapter blocks the worker. Fix: process-isolated runner with hard kill, rebuild, uncertain on kill; keep ledger replay ban. |
| 8 | Bandit config parse + scanner failure blocks CI; dependency audit runs | **Partial / likely broken** | `.bandit`, `.github/workflows/ci.yml` | `.bandit` has not been parsed by an installed Bandit; no test asserting parse/failure behavior. Fix config format, add config-parse test, CI order (Bandit → pip-audit). |

## DC-007 — Android real-device loop and Evidence

| Requirement | Status | Gap |
| --- | --- | --- |
| Capability set incl. `device.observe`, `device.screenshot`, swipe, press back/home | **Partial** | Existing IDs are `observe.*`, `ui.back/home`; add canonical `device.*` aliases/operations and swipe, keep compatibility. |
| Structured discovery/pairing (device/unauthorized/offline), fingerprint, re-pair | **Partial** | `discover_devices` parses text only; no pairing state machine, fingerprint, registration/revoke flow. |
| Accessibility observation and redacted node summary | **Missing** | UI dump only used internally for tap bounds; no node summary/model. |
| Evidence service (metadata + object storage + access control + redaction + retention) | **Missing** | Only `evidence_refs` strings; screenshots are hashed and discarded. No evidence table, object store, retrieval API or audit. |
| Real device E2E and reconnect/restart/USB replug | **BLOCKED** | No `adb`, emulator or physical device in this environment. |
| Manual takeover/pause/resume | **Partial** | Worker/local pause and fake takeover exist; no operator API/audit and no re-approval before resume. |
| Diagnostics | **Partial** | Metrics JSON and gateway health exist; no queue depth/age, adapter state, disk, last-error, trace correlation. |

## DC-008 — MindOS integration and contract governance

| Requirement | Status | Gap |
| --- | --- | --- |
| Contract comparison/mapping with MindOS legacy `DeviceCommandIntent` | **Missing** | No mapping document or code; MindOS repo not modified (dirty tree). |
| OpenAPI 3.x + JSON Schema publication | **Partial** | FastAPI exposes `/docs`/`/openapi.json` implicitly; no versioned exported artifact, no compatibility gate. |
| Reuse ai-platform event envelope or ADR | **Partial** | `device-event.v1` exists but is not compared to `ai-platform` contracts. |
| MindOS provider/connector with auth, timeout, retry, idempotency, error mapping, trace | **Partial** | Only `examples/mindos_client.py`; not wired into MindOS and not tested against its API. |
| UI state from Device Control, uncertain non-idempotent not retried | **Partial** | Documented, no MindOS UI code/tests. |
| Consumer-driven contract tests | **Missing** | No cross-repo contract tests. |

## DC-009 — Production operations

| Requirement | Status | Gap |
| --- | --- | --- |
| Docker topology/persistence/backup/disk-full/read-only/corruption | **Partial / BLOCKED** | Compose and non-root image exist; no Docker daemon here to verify. No backup/restore script or corruption test. |
| HTTPS/mTLS, credential lifecycle, secret handling | **Partial** | Token rotation/revocation exists; no HTTPS enforcement or mTLS gateway client support. |
| Preflight, upgrade signature, admin-approved upgrade, bounded offline queue | **Missing / partial** | Queue bounded; no preflight/upgrade verification tooling. |
| Device management API/UI | **Partial** | List/detail/revoke APIs; no UI. |
| Monitoring/alerting | **Partial** | JSON counters only; no heartbeat age/queue depth/uncertain alert rules. |
| Backup/restore with RPO/RTO and evidence integrity | **Missing** | No scripts/runbook execution. |

## Blockers and constraints for this execution

- No `adb`, Android emulator, physical device: DC-007 real-device and DC-009
  USB/ADB acceptance must remain **BLOCKED**.
- No Docker daemon: Docker persistence/read-only/disk-full acceptance remains
  **BLOCKED**; configuration and tests that do not need Docker can still be
  delivered.
- `mind-os` working tree has pre-existing uncommitted changes and no runtime
  available here. Cross-repo code will be limited to a Device Control-side
  provider/contract mapping plus an explicitly **BLOCKED** live E2E; no
  MindOS UI redesign and no merging of device state into MindOS.
- `ai-platform` is behind origin/main and dirty; its canonical contracts are
  copied, but no rebase is performed.

## Order of execution

1. DC-006 (release blocker): manifest authority, approval v2, device identity,
   state/verification, isolation, Bandit.
2. DC-007: evidence service/API, UI summary, diagnostics, reconnect/recovery.
3. DC-008: OpenAPI export, mapping, provider contract tests, compatibility ADR.
4. DC-009: production guardrails, preflight/upgrade/backup tools, admin
   diagnostics/UI, runbooks; mark hardware/Docker items BLOCKED until run.
