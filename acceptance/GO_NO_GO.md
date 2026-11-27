# Go / No-Go — DC-006…DC-011

Date: 2026-11-27
Baseline: `718746005827f8a371f10f631951d07dc38342aa`
Implementation commits: see `git log` on `main`.

## Decision: **NO-GO**

Automated security gates pass, but release gates B/C/D require hardware, Docker
and a live MindOS deployment that are unavailable in this environment. The
fake adapter and local filesystem evidence store are explicitly not accepted as
real-device/production PASS.

## What passed

- 114 automated tests (pytest), Ruff, mypy.
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
- DC-010: real structural screenshot redaction with re-decode and HMAC proof;
  server-side proof/hash/image verification; gateway independently derives
  allow/ask from manifest risk; Ed25519 manifest+key id/window; state
  freshness/uniqueness/quality checks; evidence storage DI + foundation-storage
  adapter; restore dry-run tool; OpenAPI constraints and dev-only compose HTTP;
  MindOS Device Control provider module/descriptor and contract tests.
- DC-011: baseline/research/selection matrix, ADR-003 boundary, adapter SPI and
  lifecycle/timeout/circuit, plugin manifest with license/SBOM/signature,
  canonical device/telemetry/twin contracts, HA pilot mapping/fixture, MQTT
  namespace/ACL helper. Design gate PASS; live platforms remain BLOCKED.

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
| A | Real Android structural redaction evidence on password/OTP/payment screens | BLOCKED |
| C | MindOS live Provider registration/TaskRun approval/evidence loop | BLOCKED |
| IoT | Home Assistant live discovery/command/reconnect/approval E2E | BLOCKED |
| IoT | MQTT broker TLS/ACL/replay PoC and real telemetry pipeline | BLOCKED |
| IoT | Platform/Adapter/Device/Twin persistence and unified endpoints | DC-012 |
| IoT | SBOM/vulnerability pipeline and license approval for ThingsBoard 4.4 | PENDING |

## Next execution steps

1. Run `docs/android/ANDROID_SETUP_AND_RUNBOOK.md` on a controlled device;
   record redacted evidence and command ids in `ACCEPTANCE-MATRIX.md`.
2. Deploy control plane + gateway behind TLS/mTLS; run preflight, revocation,
   rotation and backup/restore drills.
3. Wire MindOS provider to the real API; verify TaskRun UI fields, cancel,
   uncertain display and cross-tenant denial.
4. Re-run Bandit/pip-audit/lint/type/tests and update this report; only then
   request GO approval.
