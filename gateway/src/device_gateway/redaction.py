"""Structural screenshot redaction with a verifiable processing proof.

The adapter captures a PNG in memory, masks status/notification and sensitive
control regions from the Accessibility tree, re-encodes the image, validates
that it decodes again, and signs a proof over original/output hashes, policy and
regions. The raw frame never leaves this function.

Limits: this is structural region redaction, not OCR of arbitrary pixels. If the
tree is unavailable, truncated or quality is low, the result is `restricted`
and the caller must not upload it. A policy version and processor version are
always recorded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:  # Pillow is a gateway-only dependency
    from PIL import Image, UnidentifiedImageError
except ImportError:  # pragma: no cover - covered by unavailable-policy test
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = Exception  # type: ignore[assignment,misc]

REDACTION_POLICY_VERSION = "android-region-redaction/2026-11-27.1"
REDACTION_PROCESSOR = "pillow-region-mask/1.0"
SENSITIVE_MARKERS = ("password", "otp", "pin", "card", "cvv", "credential", "secret")
STATUS_BAR_RATIO = 0.06
MAX_REGIONS = 64


class RedactionUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class RedactionResult:
    status: str
    original_sha256: str
    output_sha256: str | None
    processor: str
    policy_version: str
    key_id: str
    regions: list[dict[str, Any]] = field(default_factory=list)
    observed_at: str = ""
    proof: str | None = None
    reason: str | None = None

    def metadata(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "original_sha256": self.original_sha256,
            "output_sha256": self.output_sha256,
            "processor": self.processor,
            "policy_version": self.policy_version,
            "key_id": self.key_id,
            "regions": self.regions,
            "observed_at": self.observed_at,
            "proof": self.proof,
            "reason": self.reason,
        }


def proof_payload(result: RedactionResult) -> dict[str, Any]:
    return {
        "original_sha256": result.original_sha256,
        "output_sha256": result.output_sha256,
        "processor": result.processor,
        "policy_version": result.policy_version,
        "key_id": result.key_id,
        "regions": result.regions,
    }


def sign_proof(result: RedactionResult, key: str) -> str:
    if len(key.encode("utf-8")) < 32:
        raise RedactionUnavailable("redaction signing key must be at least 32 bytes")
    payload = json.dumps(proof_payload(result), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_proof(result: RedactionResult, key: str) -> bool:
    if not result.proof or len(key.encode("utf-8")) < 32:
        return False
    payload = json.dumps(proof_payload(result), sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, result.proof)


def redact_png(
    data: bytes,
    *,
    nodes: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    key: str,
    key_id: str = "",
    policy_version: str = REDACTION_POLICY_VERSION,
    processor: str = REDACTION_PROCESSOR,
    allow_empty_nodes: bool = False,
) -> tuple[bytes | None, RedactionResult]:
    """Return ``(redacted_bytes, result)``; bytes are ``None`` unless redacted."""

    observed_at = datetime.now(timezone.utc).isoformat()
    original = hashlib.sha256(data).hexdigest()
    base = dict(original_sha256=original, processor=processor, policy_version=policy_version,
                key_id=key_id, observed_at=observed_at)
    if Image is None:
        return None, RedactionResult(status="failed", output_sha256=None,
                                     reason="redaction_processor_unavailable", **base)  # type: ignore[arg-type]
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            if image.format != "PNG" or image.width < 1 or image.height < 1:
                raise RedactionUnavailable("invalid_png")
            width, height = image.size
            if width * height > 20_000_000:
                raise RedactionUnavailable("image_too_large")
            canvas = image.convert("RGB")
            regions = _regions(nodes, width, height)
            if (not nodes or not regions) and not allow_empty_nodes:
                return None, RedactionResult(status="restricted", output_sha256=None,
                                             reason="ui_tree_unavailable_or_no_coverage",
                                             regions=[], **base)  # type: ignore[arg-type]
            for region in regions:
                canvas.paste((0, 0, 0), (region["x1"], region["y1"], region["x2"], region["y2"]))
            output = io.BytesIO()
            canvas.save(output, format="PNG", optimize=True)
            encoded = output.getvalue()
        with Image.open(io.BytesIO(encoded)) as check:
            check.load()
            if check.format != "PNG" or check.size != (width, height):
                raise RedactionUnavailable("redacted_image_invalid")
    except (UnidentifiedImageError, OSError, ValueError, RedactionUnavailable) as exc:
        return None, RedactionResult(status="failed", output_sha256=None,
                                     reason=type(exc).__name__, **base)  # type: ignore[arg-type]

    result = RedactionResult(
        status="redacted", output_sha256=hashlib.sha256(encoded).hexdigest(),
        regions=regions, **base,
    )
    try:
        result = RedactionResult(**{**result.__dict__, "proof": sign_proof(result, key)})
    except RedactionUnavailable:
        return None, RedactionResult(status="restricted", output_sha256=None,
                                     reason="redaction_proof_key_missing",
                                     regions=regions, **base)
    return encoded, result


def _regions(nodes: list[dict[str, Any]] | tuple[dict[str, Any], ...],
             width: int, height: int) -> list[dict[str, Any]]:
    regions: list[dict[str, Any]] = [{
        "x1": 0, "y1": 0, "x2": width,
        "y2": max(24, int(height * STATUS_BAR_RATIO)),
        "reason": "status_bar_notifications",
    }]
    for node in nodes:
        if len(regions) >= MAX_REGIONS:
            break
        if not _sensitive_node(node):
            continue
        bounds = node.get("bounds") or []
        if not isinstance(bounds, (list, tuple)) or len(bounds) != 4:
            continue
        x1, y1, x2, y2 = (max(0, int(value)) for value in bounds)
        x1, x2 = min(x1, width), min(x2, width)
        y1, y2 = min(y1, height), min(y2, height)
        if x2 > x1 and y2 > y1:
            regions.append({"x1": x1, "y1": y1, "x2": x2, "y2": y2,
                            "reason": "sensitive_control"})
    return regions


def _sensitive_node(node: dict[str, Any]) -> bool:
    if node.get("sensitive") or node.get("is_password"):
        return True
    resource = str(node.get("resource_id") or "").lower()
    if any(marker in resource for marker in SENSITIVE_MARKERS):
        return True
    return "password" in str(node.get("input_type") or "").lower()


def proof_header(result: RedactionResult) -> dict[str, str]:
    """Headers for the control-plane evidence upload."""

    return {
        "X-Original-SHA256": result.original_sha256,
        "X-Redaction-Status": result.status,
        "X-Redaction-Processor": result.processor,
        "X-Redaction-Policy": result.policy_version,
        "X-Redaction-Key-Id": result.key_id,
        "X-Redaction-Proof": result.proof or "",
        "X-Redaction-Regions": base64.b64encode(
            json.dumps(result.regions, sort_keys=True).encode()
        ).decode("ascii"),
    }
