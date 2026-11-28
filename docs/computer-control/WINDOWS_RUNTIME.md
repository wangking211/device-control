# Windows Computer Control Runtime

## Components

| Component | Path |
|---|---|
| Capability manifest | `src/device_control/computer/manifest.py` |
| Typed contracts/redaction | `src/device_control/computer/contracts.py` |
| Session detection | `src/device_control/computer/session.py` |
| Durable action ledger | `src/device_control/computer/ledger.py` |
| Runtime worker | `src/device_control/computer/runtime.py` |
| UIA provider | `src/device_control/computer/providers/uia.py` |
| Playwright provider | `src/device_control/computer/providers/playwright.py` |
| Entry point | `scripts/computer_runtime.py` |

## Enrollment (operator)

1. Create a Device Control gateway and endpoint using the existing admin APIs.
   The endpoint must report the computer capabilities from
   `computer.manifest.manifest_document()`.
2. Register the manifest through `PUT /v1/gateways/{id}/manifest`.
3. Activate the gateway and inject the one-time gateway credential into the
   Runtime secret store; never put it in CLI args or logs.
4. Set the Runtime environment:

```
DEVICE_CONTROL_URL=https://device-control.internal
DEVICE_GATEWAY_ID=computer-gw-1
DEVICE_GATEWAY_CREDENTIAL=<secret injection>
COMPUTER_TENANT=tenant-a
COMPUTER_ENDPOINT_ID=pc-endpoint-1
COMPUTER_DEVICE_ID=pc-1
COMPUTER_APP_ALLOWLIST=C:\ProgramData\MindOS\computer-apps.json
COMPUTER_PAUSE_FILE=C:\ProgramData\MindOS\computer-takeover.flag
COMPUTER_RUNTIME_LEDGER=C:\ProgramData\MindOS\computer-ledger.json
COMPUTER_BROWSER_ALLOWED_HOSTS=app.example.com
```

`COMPUTER_ALLOW_CLIPBOARD=1` is required to enable clipboard capabilities;
default is off.

## Running

```
python scripts/computer_runtime.py --once
python scripts/computer_runtime.py
```

The runtime only makes outbound HTTP calls to Device Control. It opens no
listener.

## Local pause/takeover

Create the pause file (or an operator UI action that does so) to stop accepting
new actions. Existing in-flight UI Automation calls are not interruptible; the
runtime reports them as executing/unknown and does not replay. Remove the file
to resume.

## Security boundaries

- No shell/PowerShell capability exists in v1.
- No coordinate-only click; selectors must resolve uniquely within the
  foreground window.
- Password controls and `sensitive=true` text are rejected.
- App launch is allowlisted by app id -> executable path.
- Session locked/UAC/logged-out denies actions.
- Screenshots redact explicit sensitive regions; structured data redacts keys
  containing password/token/credential/cookie/authorization.
- Ledger stores references/status only, never nonce/token/lease credential.

## Reliability hardening (DC-COMPUTER-002)

- Ledger is now `dc.computer-ledger/v2`, keyed by
  `tenant | endpoint | task | run | idempotency_key`.
- Unresolved records (`executing`, `unknown`, `uncertain`, `recovering`) are
  never evicted; at capacity new records fail closed before dispatch.
- Ledger writes use a cross-process file lock and atomic fsync/replace.
- Desktop input is guarded by a Windows named mutex scoped to the interactive
  session (`DesktopMutex`); independent Runtime processes cannot drive the same
  desktop concurrently.
- Browser submit requires a typed business postcondition; click alone is
  `executed_unverified`. Navigation can require an expected host/path.
- Provider exceptions after write dispatch become `uncertain` and require
  observation-only reconciliation.
- MindOS TaskRun does not offer an ordinary retry for unknown; a new attempt
  requires a new task/run/key and approval.

## Windows lifecycle / ACL notes

- Run the Runtime in the signed-in interactive user session, not as a
  non-interactive Windows service. A service cannot safely operate the user's
  desktop.
- Store the gateway credential in Windows Credential Manager/DPAPI; never in
  config, CLI args or logs.
- Restrict ledger, pause and health files to the interactive user's profile
  (`%LOCALAPPDATA%\MindOS\ComputerControl`) via NTFS ACL.
- Install/upgrade/uninstall lifecycle and RDP/disconnect tests require a
  dedicated Windows 11 test PC and are not executed here.


## Not implemented / blocked

- Live UIA tests require `uiautomation` and an interactive desktop; not present
  in this environment.
- Live Playwright tests require the package/browser and a display; not present.
- MSI install/upgrade/uninstall and service lifecycle are documented only; no
  signed installer was built/tested here.
- MindOS end-to-end on a dedicated test PC remains BLOCKED.
