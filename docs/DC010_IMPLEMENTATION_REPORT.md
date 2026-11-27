# DC-010 Implementation Report

Date: 2026-11-27
Baseline: device-control `7187460`; mind-os `93af90c`; ai-platform local
`932cc0a` / origin `592c71b` (not rebased, dirty pre-existing tree).

## Summary

| Stage | Delivered | Status |
| --- | --- | --- |
| DC-010-00 Rebaseline | `docs/DC010_REBASELINE.md`, interface/ownership table | PASS |
| DC-010-01 Redaction | structural mask + re-decode + HMAC proof; server re-decode/hash/proof; restricted/failed fail-closed | PASS (synthetic fixtures); real-device BLOCKED |
| DC-010-02 Gateway policy | local allow/ask derivation from manifest; upstream mismatch rejected; write requires lease+approval+nonce | PASS |
| DC-010-03 Device state | fingerprint/state/observed-at/future/quality/target uniqueness checks | PASS (unit/Fake); real device BLOCKED |
| DC-010-04 Manifest keys | Ed25519 signature, key id, revision/window, sign script; production startup requires key | PASS (unit); rotation drill BLOCKED |
| DC-010-05 Docker/OpenAPI | dev-only compose HTTP flag; constraints pins; OpenAPI export/drift test | PASS local; Docker/TLS BLOCKED |
| DC-010-06 Evidence | storage DI, foundation-storage adapter, head/list/health, backup + restore dry-run | PASS local; real object store BLOCKED |
| DC-010-07 MindOS | provider module + descriptor + contract tests in MindOS | PARTIAL; live registration/E2E BLOCKED |
| DC-010-08 Android | runbook and redaction/state/fault unit coverage | BLOCKED (no device) |

## Security/architecture decisions

- Structural redaction is the only path to upload evidence. No UI tree means
  `restricted`, not `redacted`; the server does not trust the gateway's label.
- Redaction proof is HMAC over original/output hashes, processor, policy, key id
  and region summary. The original frame is dropped before result reporting.
- Gateway policy no longer uses upstream `policy_decision` as authority; a write
  always needs a lease, approval and nonce, and `policy_decision` must match the
  locally derived decision.
- Manifest production trust is Ed25519 public-key only; HMAC is explicit
  compatibility mode.
- Evidence routes depend on `get_object_store`; `foundation` selection fails
  unavailable rather than falling back to local.

## Test results

```
python -m pytest -q                        102 passed
ruff check ...                             All checks passed
mypy ...                                   Success: no issues (27 files)
bandit -c .bandit -r src gateway/src       0 issues (only B101 skipped)
pip-audit -r requirements/audit.txt        No known vulnerabilities
```

MindOS provider test:
`tests/test_device_control_provider_dc010.py` → 3 passed with
`PYTHONPATH=edge-agent;packages/contracts`.

## Uncovered / blocked

- Real Android screenshots for password/OTP/payment/notification, rotation,
  low-resolution/blur, OCR timeout (no hardware; structural mask does not OCR).
- Docker profile/read-only/volume/TLS/mTLS and network isolation.
- Live MindOS provider registration, TaskRun UI, approval UX, cancel/evidence
  loop and cross-tenant live checks.
- Production object storage (S3/COS) and a real restore drill with RPO/RTO.
- CI remote run; local jobs are green but GitHub Actions was not executed here.

Decision: **NO-GO** while the blocked rows remain; do not map blocked rows to
PASS with fixtures.
