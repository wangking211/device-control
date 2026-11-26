# DC-004 — Android Gateway MVP

Status: adapter and worker **implemented and tested against the fake adapter
and a stubbed adb binary**. Real emulator/USB/Wi-Fi acceptance is **BLOCKED**
in this environment (no Android SDK/adb/device). Emulator-only is not
real-device acceptance.

## Architecture

Run `device_gateway` on a trusted workstation/edge host. It connects to the
Android device through USB ADB or explicitly paired Wi-Fi ADB. ADB subprocesses
exist only in the gateway; the FastAPI control plane never invokes them.

```
gateway process
  ├── control_client (outbound HTTPS)
  ├── worker (revalidate → execute → verify → report)
  ├── dedupe ledger (SQLite, /data)
  ├── bounded queue
  └── adapter: AndroidAdbAdapter → [adb, -s, <serial>, ...]
```

## Capability manifest (v1.0.0)

| ID | Risk | Purpose | Verification |
| --- | --- | --- | --- |
| `observe.screenshot` | read | hash + byte count, raw frame discarded | screenshot predicate |
| `observe.foreground_app` | read | foreground package | read-after-write |
| `app.launch` | read | launch operator-allowlisted app | UI state |
| `ui.tap` | write | semantic target or bounded coordinate fallback | UI state |
| `ui.type_text` | write | non-secret text, bounded 500 chars | read-after-write |
| `ui.back` / `ui.home` | write | navigation | UI state |
| `ui.wait_for` | read | wait for expected app/window | UI state |

The model cannot invent capability IDs, bounds or raw ADB commands. Bounds are
validated as four integers in range and must form a non-empty rectangle.
`ui.tap` requires a state hash; the adapter re-screenshots and refuses if the
screen changed.

## Explicit exclusions

- No password/OTP/payment/banking/credential entry; secret target types are
  denied before any subprocess call.
- No silent send/publish/purchase; high-risk actions require a human approval
  in the control plane (`ask`) and are rechecked at the gateway.
- No security-setting changes, factory reset, wipe or destructive actions
  (`destructive`/`safety_critical` risk tiers are denied by the gateway).
- No arbitrary shell exposed to an agent; the capability surface is closed.
- No unrestricted coordinate loops or background surveillance.
- R3 operations default-deny for general agents.

## Driver isolation and safety

- `adb_path` and `serial` are operator configuration, never command input.
- Every call uses an argument array with `shell=False`, a timeout and bounded
  output (default 2 MiB; screenshots 8 MiB).
- Text input rejects shell metacharacters and unsupported characters; spaces
  are encoded as `%s` for `adb shell input text`.
- Screenshots are hashed and discarded; evidence is a hash reference, with
  gateway-managed opt-in retention. Raw frames never reach the control plane.
- Secret-field and blocklisted-app markers are enforced in both control-plane
  policy and gateway preflight.
- User takeover (`adapter.health().takeover`) pauses the worker locally, marks
  the gateway degraded and rejects in-flight/new work with `user_takeover`.
- Disconnect after an action returns `uncertain`; it is never blindly retried.
- Adapter exceptions are isolated; the control plane stays up.

## Support matrix (to be filled with real-device evidence)

| Item | Expected | Evidence |
| --- | --- | --- |
| Android versions / API levels | TBD by operator | **BLOCKED** |
| OEM/model | TBD | **BLOCKED** |
| platform-tools version | pin in gateway image | **BLOCKED** |
| USB pairing | `adb devices -l` shows `device` | **BLOCKED** |
| Wi-Fi pairing | explicit `adb pair`/`connect` | **BLOCKED** |
| Verified capabilities | manifest above | fake adapter PASS; real device **BLOCKED** |

## Adapter test coverage (without hardware)

- argv construction: `[adb, "-s", serial, ...]`, `shell=False`, timeout,
  `stdin=DEVNULL`;
- `mksCurrentFocus` parsing, screenshot hash/byte cap, no raw frame retained;
- non-allowlisted app rejected without subprocess;
- secret field rejected without subprocess;
- unsafe text rejected without subprocess;
- adb timeout → `AdapterTimeout` (uncertain);
- invalid bounds/serial rejected;
- `UI dump` bounds parsing.

## Real-device procedure (to execute when hardware is available)

1. Install platform-tools, enable USB debugging, authorise the host key.
2. `adb devices -l` and record `serial`, `ro.build.version.release`,
   `ro.build.version.sdk`, model and OEM.
3. Start the gateway with `DEVICE_GATEWAY_ADAPTER=android`,
   `DEVICE_GATEWAY_SERIAL=<serial>`, `DEVICE_GATEWAY_ALLOWED_APPS=<pkg>`.
4. Verify heartbeat online and manifest inventory in `GET /v1/gateways/{id}`.
5. Run the harmless scenario: launch allowlisted app, observe, tap a semantic
   target, verify, screenshot hash.
6. Negative checks: change screen after approval; user takeover; unplug USB
   mid-command; secret field; non-allowlisted app; timeout.
7. Record evidence (serial redacted, Android version, command ids, redacted
   screenshot hashes) in `acceptance/ACCEPTANCE-MATRIX.md`.

Do not perform physical-device writes without explicit authorization.
