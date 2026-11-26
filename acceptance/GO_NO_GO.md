# Go / No-Go — DC-006…DC-009

Date: 2026-11-26
Baseline: `cb13f8b1e64ad60077191ec47653f57f545b180f`
Implementation commit: see `git log -1 --format=%H` on `main`.

## Decision: **NO-GO**

Automated security gates pass, but release gates B/C/D require hardware, Docker
and a live MindOS deployment that are unavailable in this environment. The
fake adapter and local filesystem evidence store are explicitly not accepted as
real-device/production PASS.

## What passed

- 87 automated tests (pytest), Ruff, mypy.
- Bandit 1.9.4 clean; config skips only `B101`; targeted `# nosec` on fixed
  subprocess/parameterized SQL lines.
- `pip-audit -r requirements/audit.txt`: no known vulnerabilities.
- DC-006: manifest authority/digest/signature, device binding, approval v2
  (nonce/state/device), sensitive-control detection, `executed_unverified`,
  process-isolated hard timeout and uncertain replay ban.
- DC-007 (fake/local): redacted Accessibility observation, evidence metadata +
  object store + hash/download/retention, diagnostics/alerts.
- DC-008: OpenAPI export, MindOS intent mapping, provider contract tests.
- DC-009: HTTPS enforcement, preflight, signed upgrade verification, SQLite
  backup/restore tooling, admin shell, alerts.

## Blocking rows (must be executed before GO)

| Gate | Item | Status |
| --- | --- | --- |
| B | One real Android device full loop (discover→pair→observe→screenshot→launch→tap/type→verify→evidence) | BLOCKED (no adb/device/emulator) |
| B | USB/Wi-Fi pairing, takeover, unplug, reboot/reconnect reconciliation | BLOCKED |
| B | Durable object storage for Evidence | BLOCKED (local FS adapter only) |
| C | Live MindOS API call and TaskRun/command/evidence E2E | BLOCKED (no MindOS runtime; dirty tree) |
| D | Docker start/restart persistence, read-only/disk-full/db-corruption drills | BLOCKED (no Docker) |
| D | TLS/mTLS termination and credential rotation on the deployed ingress | BLOCKED |
| D | Backup/restore drill with RPO/RTO on production-like volumes | BLOCKED |

## Next execution steps

1. Run `docs/android/ANDROID_SETUP_AND_RUNBOOK.md` on a controlled device;
   record redacted evidence and command ids in `ACCEPTANCE-MATRIX.md`.
2. Deploy control plane + gateway behind TLS/mTLS; run preflight, revocation,
   rotation and backup/restore drills.
3. Wire MindOS provider to the real API; verify TaskRun UI fields, cancel,
   uncertain display and cross-tenant denial.
4. Re-run Bandit/pip-audit/lint/type/tests and update this report; only then
   request GO approval.
