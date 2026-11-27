# Screenshot Redaction and Evidence Privacy (DC-010-01)

## Pipeline

1. `device.screenshot` captures PNG bytes in the gateway memory only.
2. The adapter obtains the UIAutomator node summary for the same frame.
3. `device_gateway.redaction.redact_png` masks:
   - the status/notification bar region (top 6%);
   - every sensitive node region (`sensitive`, password input type, or
     password/OTP/card/PIN/credential/secret resource-id marker).
4. The masked image is re-encoded as PNG, decoded again, and dimensions/format
   are checked. Any failure or unavailable UI tree returns `failed`/`restricted`.
5. A HMAC proof is signed over original hash, output hash, processor, policy,
   key id and region summary. The original frame is never returned to the worker
   and never uploaded.
6. The control plane re-decodes PNG, verifies the output hash and proof, and
   rejects `restricted`, missing proof, unknown policy or mismatched hash.
7. Evidence metadata stores original hash (metadata only), output hash,
   processor, policy, key id, proof and region summary. Content is immutable
   and hash-verified on read.

## Status semantics

| Status | Upload allowed | Download |
| --- | --- | --- |
| `redacted` + valid proof | yes | tenant command scope |
| `restricted` / `failed` | no | no object exists |

`not_required` is accepted only for non-image artifact logs.

## Limitations

- This is structural region redaction, not OCR of arbitrary pixels. A WebView or
  custom Canvas that exposes no nodes yields `restricted` rather than a false
  `redacted`.
- A screenshot with no UI tree is rejected even if the status bar was masked,
  because absence of detected sensitive nodes is not proof of sufficient
  redaction.
- The redaction key is a gateway-only secret shared with the control plane for
  proof verification; production may replace it with an asymmetric processor
  proof without changing metadata fields.

## Tests

`gateway/tests/test_redaction.py`: region masking, proof roundtrip, tamper,
empty-tree restricted, invalid image failed.
`tests/test_evidence.py`: proof required, tamper rejected, unredacted rejected,
hash/MIME checks, content hash verification.
