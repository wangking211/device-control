# Android Gateway Setup and Runbook (DC-007)

Hardware acceptance is **BLOCKED** in this environment: no `adb`, emulator or
physical device. The commands below are the reproducible procedure; record
output in `acceptance/ACCEPTANCE-MATRIX.md` when hardware is available.

## 1. Register the gateway and manifest (control plane)

```bash
python scripts/bootstrap_gateway.py \
  --control-url https://device-control.internal \
  --admin-token "$DEVICE_CONTROL_ADMIN_TOKEN" \
  --tenant tenant-a --gateway gateway-a
```

The operator registers the exact manifest (signed in production):

```bash
python - <<'PY'
import json, os, sys
sys.path.insert(0, "gateway/src")
from device_gateway import manifest
doc = manifest.default_document()
key = os.environ.get("DEVICE_CONTROL_MANIFEST_HMAC_KEY", "")
if key:
    doc["signature"] = manifest.sign(manifest.digest(doc), key)
print(json.dumps(doc, indent=2))
PY
```

`PUT /v1/gateways/gateway-a/manifest` with that document. The gateway must use
the same manifest/digest (`DEVICE_GATEWAY_MANIFEST` or built-in) and the same
HMAC key. Heartbeat digest drift moves the gateway to `degraded` and blocks pull.

## 2. Enroll the one device

The first supported topology is one gateway = one Android device.

```bash
# Operator obtains the fingerprint from the gateway display/health output
export DEVICE_GATEWAY_ENDPOINT_ID=phone-1
export DEVICE_GATEWAY_DEVICE_ID=device-phone-1
export DEVICE_GATEWAY_DEVICE_FINGERPRINT=<sha256 from observe/health>

# Enroll endpoint with the same gateway/device/fingerprint
curl -X POST https://device-control.internal/v1/endpoints \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"endpoint_id":"phone-1","tenant_ref":"tenant-a","gateway_id":"gateway-a",
       "protocol_version":"v1","device_id":"device-phone-1",
       "device_fingerprint":"<same>","capabilities":[...]}'
```

Changing the serial/fingerprint requires revoking and re-pairing the endpoint;
the gateway rejects commands for a different endpoint/device.

## 3. Start the gateway

```bash
export DEVICE_CONTROL_URL=https://device-control.internal
export DEVICE_GATEWAY_ID=gateway-a
export DEVICE_GATEWAY_CREDENTIAL=<one-time credential>
export DEVICE_GATEWAY_ADAPTER=android
export DEVICE_GATEWAY_ADB_PATH=/usr/bin/adb
export DEVICE_GATEWAY_SERIAL=<device serial>
export DEVICE_GATEWAY_ALLOWED_APPS=com.example.notes
export DEVICE_GATEWAY_ENDPOINT_ID=phone-1
export DEVICE_GATEWAY_DEVICE_ID=device-phone-1
export DEVICE_GATEWAY_DEVICE_FINGERPRINT=<sha256>
export DEVICE_GATEWAY_MANIFEST_HMAC_KEY=<same signing key or empty in dev>
export DEVICE_GATEWAY_PROCESS_ISOLATION=1
python scripts/gateway_preflight.py --json
python -m device_gateway.main --once
```

`--once` performs heartbeat, pull, revalidate, execute, verify and report. It
uses a short-lived child process per adapter call with a hard timeout.

## 4. Acceptance scenario (harmless only)

1. Observe (`device.observe`) and screenshot (`device.screenshot`); confirm
   evidence metadata/hash and redacted node summary.
2. Launch an allowlisted app; verify foreground package.
3. Approve `ui.tap` on `button-continue` with the observed state hash/version;
   execute; confirm UI changed and command verified.
4. Type non-secret text into `field-search`; confirm only text length is in the
   result. Attempt `field-password` and confirm rejection.
5. Force device fingerprint change (different device/serial) and confirm
   rejection/re-pairing.
6. Unplug USB mid-command; confirm `uncertain`, then confirm no automatic
   replay. Reconnect and confirm reconcile/heartbeat.
7. User takeover: interact with the device; confirm gateway pauses/degraded and
   rejects new actions until operator resume.

Do **not** test payments, messages, deletion, account or security settings.

## 5. Diagnostics

`GET /v1/gateways/{id}/diagnostics` includes heartbeat age, queue depth/age,
manifest digests, last error, health and adapter inventory. Alerts:
`GET /v1/alerts`.

## 6. Evidence

Screenshots are uploaded as redacted PNG evidence to the control plane's object
store; metadata, hash, size, retention and access audit are in Device Control.
See `docs/EVIDENCE_STORE.md`. If upload fails, the command is not reported as
success.
