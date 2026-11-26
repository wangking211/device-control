# UI State and Verification (DC-006 / DC-007)

## Observation model

The gateway returns a redacted, structural observation:

```json
{
  "source": "uiautomator",
  "quality": "high",
  "observed_at": "2026-11-26T12:00:00+00:00",
  "foreground_app": "com.example.notes",
  "screen": "awake",
  "device_fingerprint": "sha256:...",
  "state_hash": "sha256 over foreground+screen+nodes",
  "state_version": "v1:<hash prefix>",
  "nodes": [
    {"resource_id": "field-search", "class_name": "android.widget.EditText",
     "bounds": [20,100,700,180], "clickable": true, "editable": true,
     "sensitive": false, "input_type": "text", "depth": 5,
     "visible": true, "text_length": 0}
  ]
}
```

Text and content descriptions are never included; only `text_length` is
exposed. `source`/`quality` make low-confidence observation explicit
(WebView/Canvas/permission gaps).

## Freshness and binding

- Capabilities with `requires_state` require `state_hash` and `state_version`.
- The gateway re-observes immediately before execution and compares both.
- `state_max_age_ms` (default 15s) rejects stale observations.
- The device fingerprint is observed locally and compared to the command and
  configured binding; a mismatch requires re-pairing.

## Sensitive controls

Sensitivity comes from the observed node, not caller metadata:

- `sensitive=true` (UIAutomator `password`), password/numberPassword input type,
  or resource-id markers (`password`, `otp`, `pin`, `card`, `cvv`, credential,
  secret) deny text injection;
- unknown or non-editable targets fail closed (`target_unverified` /
  `target_not_editable`);
- caller `target_type=password/otp/...` is an additional deny, never a bypass.

## Verification by capability

| Capability | Success requires |
| --- | --- |
| `device.observe` | readable state with a non-empty hash |
| `device.screenshot` | valid PNG signature, size/bytes cap, hash; evidence upload |
| `app.launch` | expected foreground package after bounded wait |
| `ui.tap` | post-state hash differs from pre-state (or explicit predicate); otherwise `executed_unverified` |
| `ui.type_text` | target is editable/non-sensitive and text length changes; value never returned |
| `ui.swipe` / press back/home | post-state hash changes |
| `ui.wait_for` | expected app/window observed before timeout |

`executed_unverified` maps to command `uncertain` with reason; it is never
`succeeded`. `succeeded` requires a verification object with method,
`verified=true`, and timestamp (and `adapter_guarantee=true` for ACK-only).

## Known limits

- UIAutomator does not expose `inputType`; class/password attributes are used.
- WebView/Canvas content may not appear as nodes; state-bound actions fail
  closed.
- Accessibility service alternatives require a separate permission review.
