# DC-COMPUTER-001 Acceptance

Date: 2026-11-28
Repo: `device-control`

## Scope delivered

Windows Computer Control Runtime skeleton, capability manifest, typed provider
contract, UIA and Playwright providers, session detection, durable action
ledger, runtime worker, docs/ADR and unit/security tests.

No production physical writes are enabled. No live Windows PC, UIA desktop,
Playwright browser or signed installer was available for E2E.

## Matrix

| ID | Test | Result | Evidence / limitation |
|---|---|---|---|
| W01 | Enroll dedicated Windows PC | BLOCKED | Enrollment reuses gateway APIs; no test PC/gateway here |
| W02 | Runtime reconnect after network loss | PARTIAL | Outbound worker loop; no network-loss test |
| W03 | Locked/logged-out desktop | PASS (unit) | `session.py` denies; runtime test |
| W04 | Observe active window/UIA tree | PARTIAL | UIA provider implemented; uiautomation/desktop absent |
| W05 | Screenshot secret redaction | PASS (unit) | `redact_image` pixel test + structured redaction sentinel |
| W06 | Launch allowlisted app | PARTIAL | Allowlist + verify code; no live process/window |
| W07 | Click stable UIA element | PARTIAL | Unique selector + post-check; no live UIA |
| W08 | Selector missing | PASS (design) | No coordinate fallback; missing/ambiguous returns safe failure |
| W09 | Coordinate fallback | PARTIAL | Intentionally not implemented in v1; no blind clicks |
| W10 | Type text | PARTIAL | Password/sensitive rejection + value verify; no live UIA |
| W11 | Browser navigate/inspect | PARTIAL | Playwright provider; package/browser absent |
| W12 | Form fill and preview | PARTIAL | Fill/value verify; no live browser |
| W13 | External submit/publish approval | PASS (design) | `browser.submit` is write risk; runtime only executes Device Control-authorized envelope |
| W14 | Cancel before action | PARTIAL | Device Control cancel-before-dispatch path; runtime has no cancel channel |
| W15 | Cancel after dispatch | PARTIAL | Provider cancel returns `too_late`; live race not tested |
| W16 | Runtime crash after dispatch | PASS (unit) | Ledger `executing` → uncertain, no replay |
| W17 | Two Agents request same desktop | PASS (unit) | Runtime mutex serializes actions |
| W18 | Wrong tenant/device/task/run | PASS (unit) | Binding mismatch rejection |
| W19 | Revoke device while online | PARTIAL | Credential revocation stops pull; no live revoke |
| W20 | Local user takeover/pause | PASS (unit) | Pause/takeover file rejects new actions |
| W21 | MCP provider unavailable | PASS (design) | No MCP provider in v1; browser/desktop independent |
| W22 | Local Agent absent | PASS (design) | Base runtime does not depend on Codex/OpenCode |
| W23 | Arbitrary shell request | PASS (unit) | Shell capability absent; rejected |
| W24 | Install/upgrade/uninstall | BLOCKED | No signed installer/service lifecycle test |

## Verification

```
python -m pytest -q                         # full Device Control suite (see report)
ruff check src tests gateway scripts        # clean
mypy src/device_control/computer ...         # clean
bandit -c .bandit -r src gateway/src        # no issues
pip-audit -r requirements/audit.txt         # no known vulnerabilities
```

Focused: `tests/test_computer_runtime.py` covers manifest risk/allowlist, shell
absence, action fingerprint, locked session, takeover pause, binding mismatch,
success/evidence, duplicate delivery, crash-after-dispatch, provider exception,
ledger persistence/corruption, health and desktop mutex.

## Conclusion

Security/safety invariants are implemented and unit-tested. All live Windows PC,
UIA, Playwright, installer and MindOS TaskRun gates remain BLOCKED/PARTIAL.
Overall **NO-GO** for production computer control; production writes stay off.
