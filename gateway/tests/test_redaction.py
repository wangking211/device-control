import hashlib
import io

from device_gateway.redaction import (
    RedactionResult,
    redact_png,
    sign_proof,
    verify_proof,
)
from PIL import Image

KEY = "gateway-redaction-test-key-0123456789abcdef"
KEY_ID = "test-key-1"


def png(size=(240, 360)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, (255, 255, 255)).save(buffer, format="PNG")
    return buffer.getvalue()


def nodes():
    return [
        {"resource_id": "field-password", "bounds": [20, 200, 220, 260],
         "sensitive": True},
        {"resource_id": "button", "bounds": [20, 300, 200, 340], "sensitive": False},
    ]


def test_redaction_masks_status_bar_and_sensitive_region_with_proof():
    raw = png()
    output, result = redact_png(raw, nodes=nodes(), key=KEY, key_id=KEY_ID)
    assert output is not None
    assert result.status == "redacted"
    assert result.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.output_sha256 == hashlib.sha256(output).hexdigest()
    assert any(region["reason"] == "status_bar_notifications" for region in result.regions)
    assert any(region["reason"] == "sensitive_control" for region in result.regions)
    assert verify_proof(result, KEY)
    image = Image.open(io.BytesIO(output))
    assert image.getpixel((100, 230)) == (0, 0, 0)
    assert image.getpixel((100, 10)) == (0, 0, 0)


def test_redaction_without_tree_or_proof_key_is_restricted():
    output, result = redact_png(png(), nodes=[], key=KEY)
    assert output is None
    assert result.status == "restricted"
    assert result.proof is None

    output, result = redact_png(png(), nodes=nodes(), key="")
    assert output is None
    assert result.status == "restricted"
    assert result.reason == "redaction_proof_key_missing"


def test_tampered_proof_and_invalid_image_fail_closed():
    output, result = redact_png(png(), nodes=nodes(), key=KEY, key_id=KEY_ID)
    assert output is not None
    tampered = RedactionResult(**{**result.__dict__, "output_sha256": "0" * 64})
    assert not verify_proof(tampered, KEY)

    output, failed = redact_png(b"not-a-png", nodes=nodes(), key=KEY)
    assert output is None
    assert failed.status == "failed"


def test_signed_proof_roundtrip():
    result = RedactionResult(
        status="redacted", original_sha256="a" * 64, output_sha256="b" * 64,
        processor="p", policy_version="v", key_id="k", regions=[],
    )
    signed = RedactionResult(**{**result.__dict__, "proof": sign_proof(result, KEY)})
    assert verify_proof(signed, KEY)
    assert not verify_proof(signed, "other-key-0123456789abcdef012345")
