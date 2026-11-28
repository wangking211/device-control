# ADR-005: Windows Computer Control Runtime

Status: Accepted for first-release implementation
Repo: `device-control`

## Decision

Windows Computer Control is an isolated capability inside `device-control`,
implemented as:

- a local outbound-only Runtime process (`scripts/computer_runtime.py`);
- a replaceable provider contract (`computer/providers/base.py`);
- Windows UIA provider (native desktop) and Playwright provider (browser);
- the existing Device Control gateway command/lease/approval/evidence channel.

No new task engine, registry, lease manager or policy engine is introduced.
MindOS continues to own Task/TaskRun/approval UX. The Runtime does not plan and
does not decide authorization.

## Why reuse the gateway channel

Device Control already provides gateway enrollment, scoped credentials,
heartbeat, manifest capabilities, leases, approvals, command transitions,
idempotency and evidence upload. A new transport/scheduler would duplicate those
invariants and weaken fail-closed behavior. The Runtime is therefore a gateway
worker: outbound pull/progress/result/evidence, no inbound listener.

## Providers

- `UiaProvider`: AutomationId/Name/ControlType selectors; unique target
  required; no coordinate-only click; password controls rejected; allowlisted
  app launch only; explicit key allowlist; clipboard off by default.
- `PlaywrightProvider`: isolated browser context; semantic locators; http/https
  only; host allowlist optional; no sensitive fill in v1; submit is a separate
  risk capability.
- Optional Windows-MCP/local-agent bridges are intentionally **not** in v1.
  They must implement the same provider contract if added later.

## Capability manifest

`computer/manifest.py` defines risk tiers and schemas. Shell is absent
(`SHELL_CAPABILITIES` is empty). External side effects such as `browser.submit`
remain write capabilities requiring Device Control approval. Coordinate fallback
is not implemented in v1, so there is no blind click path.

## Runtime safety

- Interactive session check before every action; locked/UAC/logged-out denies.
- One desktop mutex per runtime process.
- Local pause/takeover file blocks new actions and audits via rejection reason.
- Durable action ledger: before dispatch `executing`; after dispatch terminal or
  `unknown`. A restart after crash returns `uncertain` and never repeats.
- Unknown/ambiguous results are never automatically replayed; Device Control
  remains authoritative.
- Evidence is uploaded through Device Control; screenshots are redacted by
  explicit regions and structured outputs redact secret-like keys.
- No token/nonce/lease credential is written to ledger, logs, events or UI.

## Consequences

- Live Windows UIA/Playwright and installer lifecycle require a dedicated test
  PC; these remain BLOCKED in this environment.
- Operators must enroll a gateway/endpoint and register the computer manifest
  before commands can route. This uses existing Device Control APIs.
