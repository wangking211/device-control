# ADR-006: Computer Control Reliability and Cross-Process Safety

Status: Accepted (DC-COMPUTER-002)
Repo: `device-control`

## Ledger identity and retention

`dc.computer-ledger/v2` keys entries by
`tenant | endpoint | task | run | idempotency_key`. Task and run are mandatory
for runtime commands. A changed request fingerprint under the same scoped key
fails closed. Legacy v1 entries are loaded as unresolved `unknown` records with
empty task/run, so they can never match a new action or become replayable.

Unresolved phases (`executing`, `unknown`, `uncertain`, `recovering`) are never
evicted. At capacity the ledger refuses new records (`LedgerCapacity`) before
dispatch. Writes re-read under a cross-process file lock, write a temp file,
fsync, chmod 0600 where supported, and atomically replace.

## Truthful verification

Dispatch, provider completion, UI verification and business postcondition are
separate. Browser navigation checks an optional expected host/path; fill requires
a unique locator and verifies the value; submit requires a typed postcondition
(`url_matches`, `text_contains`, `receipt_id`, `selector_visible`). A click
alone is `executed_unverified`, never `succeeded`. UIA click/type requires a
unique target and post-action check; password/sensitive text is rejected.

Provider exceptions after a write dispatch that may have caused side effects are
`uncertain` / `reconcile_required`. Evidence upload failure is recorded as an
evidence gap and never retries the action.

## Cross-process desktop ownership

`DesktopMutex` uses a Windows named mutex scoped to the interactive session id
(`Local\MindOS.ComputerControl.Desktop.<session>`). The Runtime must acquire it
around every provider action; failure reports `desktop_busy` without dispatch.
Abandoned mutex does not prove the previous action did not occur; the ledger's
`executing` record is converted to `unknown` on restart and reconciled by
observation only. The test suite includes two independent processes for both
the mutex and ledger writes on Windows.

## Approval

Device Control remains authoritative: command creation consumes a single-use
approval bound to tenant/endpoint/device/task/run/capability/action fingerprint;
gateway delivery only happens after authorization. The Runtime additionally
requires a non-empty approval reference for high-risk capabilities
(`browser.submit`, clipboard read/write) as defense in depth; a plain envelope
cannot manufacture approval.

## Remaining live gates

Windows 11 UIA/Playwright, signed launcher/MSI lifecycle, RDP/fast-user-switch,
Excel and browser live acceptance remain BLOCKED without the dedicated test PC.
