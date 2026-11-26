import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _module_available(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def test_bandit_config_parses_and_does_not_expand_skips():
    yaml = pytest.importorskip("yaml")
    config = yaml.safe_load((ROOT / ".bandit").read_text(encoding="utf-8"))
    assert config["skips"] == ["B101"]
    assert set(config["exclude_dirs"]) == {"tests", "gateway/tests", "scripts", "examples"}


@pytest.mark.skipif(shutil.which("bandit") is None and not _module_available("bandit"),
                    reason="bandit is not installed in this environment")
def test_bandit_fails_on_a_real_issue(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-c", str(ROOT / ".bandit"), "-r", str(tmp_path)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert "B307" in result.stdout or "B307" in result.stderr


@pytest.mark.skipif(shutil.which("bandit") is None and not _module_available("bandit"),
                    reason="bandit is not installed in this environment")
def test_bandit_passes_on_the_isolated_adapter_contract():
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-c", str(ROOT / ".bandit"), "-r",
         str(ROOT / "gateway" / "src" / "device_gateway" / "adapters" / "base.py")],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stdout
