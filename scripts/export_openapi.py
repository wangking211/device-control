"""Export the versioned OpenAPI document for consumers (MindOS, gateway, ops).

    python scripts/export_openapi.py [--out contracts/openapi-v1.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "contracts" / "openapi-v1.json"))
    args = parser.parse_args()
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from device_control.app import app

    document = app.openapi()
    document["info"]["version"] = "v1"
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {target} ({len(document.get('paths', {}))} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
