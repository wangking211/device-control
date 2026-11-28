"""Screenshot and structured-data redaction helpers."""

from __future__ import annotations

import io
from typing import Any


def redact_image(image: Any, regions: list[list[int]] | None = None) -> bytes:
    """Black out explicit regions and return PNG bytes.

    OCR-based automatic secret detection is intentionally out of scope for v1;
    callers must pass sensitive field regions or use provider-level masking.
    """

    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    for region in (regions or [])[:64]:
        if isinstance(region, list) and len(region) == 4:
            try:
                box = tuple(max(0, int(value)) for value in region)
            except (TypeError, ValueError):
                continue
            draw.rectangle(box, fill="black")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


__all__ = ["redact_image"]
