# DC-COMPUTER-002 Acceptance

Date: 2026-11-28
Repo: `device-control`

## Matrix

| ID | Scenario | Result | Evidence |
|---|---|---|---|
| L01 | Same scoped key redelivery | PASS | Runtime duplicate test; one action |
| L02 | Same key, different task | PASS | Ledger key includes task |
| L03 | Same key, different run | PASS | Ledger key includes run |
| L04 | Same scope, altered fingerprint | PASS | Fingerprint conflict test |
| L05 | Ledger full with unknown records | PASS | Unknown retained; capacity fails closed |
| L06 | Crash after dispatch | PASS | `executing` → unknown, no replay |
| L07 | Two processes write ledger | PASS (Windows) | Cross-process ledger test |
| L08 | Submit click but no success marker | PASS | Typed postcondition missing/not observed → unverified |
| L09 | Submit with valid receipt | PASS | Receipt postcondition test |
| L10 | Navigate wrong host/path | PASS | Expected URL mismatch → unverified |
| L11 | UIA selector matches multiple controls | PARTIAL | Unique-target code; no live UIA multi-match test |
| L12 | UIA exception after possible click | PARTIAL | Write exceptions → uncertain; no live post-click exception |
| L13 | Two Runtime processes target one desktop | PASS (Windows) | Named mutex cross-process test |
| L14 | Mutex owner crashes | PARTIAL | Abandoned mutex + ledger semantics; no live crash drill |
| L15 | Missing/expired submit approval | PASS (server) | Existing Device Control approval/lease tests; Runtime defense check |
| L16 | Approval replay | PASS (server) | Existing single-use consume tests |
| L17 | Approval wrong task/run/device | PASS (server) | Existing binding digest tests |
| L18 | Action changed after approval | PASS (server) | Existing approval binding tests |
| L19 | Clipboard read without permission | PASS | High-risk approval check + provider default disabled |
| L20 | Local takeover with queued command | PASS | Pause file rejection test |
| L21 | Locked/UAC/secure desktop | PASS | Session detection + locked rejection test |
| L22 | Evidence upload fails | PASS | No replay; evidence gap test |
| L23 | MindOS unknown projection | PARTIAL | Device panel shows unknown/reconcile; no live browser E2E |
| L24 | Reconcile unknown | PASS | Observation-only method test |
| L25 | Explicit retry after resolution | PARTIAL | New run/key supported by contract; no UI action |
| L26 | Install/upgrade/uninstall | BLOCKED | No signed launcher/MSI/test PC |
| L27 | RDP disconnect/fast user switch | BLOCKED | No RDP/session drill |
| L28 | Live Excel task | BLOCKED | No UIA/Excel test PC |
| L29 | Live browser form preview | BLOCKED | No Playwright/display |
| L30 | Live approved submit | BLOCKED | No dedicated Windows 11 PC |

## Verification

```
device-control pytest                 270 passed
computer runtime focused tests        22 passed
ruff / mypy / bandit                  clean / 54 files / no issues
pip-audit                             no known vulnerabilities
OpenAPI                               no drift
```

New focused coverage: ledger task/run scoping, capacity fail-closed, Windows
cross-process ledger and named mutex, browser submit postcondition, navigation
path verification, approval-required high-risk actions, observation-only
reconcile, evidence upload failure without replay.

## Conclusion

P0 reliability code gates are implemented and unit/integration tested on
Windows for the ledger and named mutex. Live Windows 11 UIA/Playwright, Excel,
RDP/fast-user-switch, installer lifecycle and MindOS browser E2E remain
BLOCKED. Overall **NO-GO**; production computer control stays off.
