import io
import subprocess

import pytest
from device_gateway.adapters.android_adb import AdbSettings, AndroidAdbAdapter
from device_gateway.adapters.base import AdapterError, AdapterTimeout
from PIL import Image

UI_XML = b"""<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
  <node class="android.widget.FrameLayout" bounds="[0,0][1080,1920]" text="">
    <node class="android.widget.EditText" resource-id="field-search" bounds="[20,100][700,180]"
          text="hello" clickable="true" password="false" visible-to-user="true" />
    <node class="android.widget.EditText" resource-id="field-password" bounds="[20,220][700,300]"
          text="" clickable="true" password="true" visible-to-user="true" />
    <node class="android.widget.Button" resource-id="button-continue" bounds="[20,340][700,420]"
          text="Continue" clickable="true" password="false" visible-to-user="true" />
  </node>
</hierarchy>"""


class FakeCompleted:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def adapter(**overrides):
    settings = AdbSettings(
        adb_path="C:/platform-tools/adb.exe",
        serial="emulator-5554",
        allowed_apps=frozenset({"com.example.notes"}),
        command_timeout_seconds=5.0,
        redaction_key="gateway-redaction-test-key-0123456789abcdef",
        redaction_key_id="test-key-1",
    )
    if overrides:
        settings = AdbSettings(**{**settings.__dict__, **overrides})
    return AndroidAdbAdapter(settings)


def fake_run_factory(calls):
    buffer = io.BytesIO()
    Image.new("RGB", (240, 360), (255, 255, 255)).save(buffer, format="PNG")
    png = buffer.getvalue()

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        joined = " ".join(command)
        if "uiautomator dump" in joined:
            return FakeCompleted(stdout=b"UI hierchary dumped to: /sdcard/window_dump.xml")
        if "window_dump.xml" in joined:
            return FakeCompleted(stdout=UI_XML)
        if "dumpsys window" in joined:
            return FakeCompleted(
                stdout=b"  mCurrentFocus=Window{abc u0 com.example.notes/com.example.NotesActivity}"
            )
        if "dumpsys power" in joined:
            return FakeCompleted(stdout=b"  mWakefulness=Awake")
        if "getprop" in joined:
            return FakeCompleted(stdout=b"test-value")
        if "screencap" in joined:
            return FakeCompleted(stdout=png)
        return FakeCompleted(stdout=b"device\n")
    return fake_run


def test_adb_invocation_uses_argument_arrays_and_no_shell(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", fake_run_factory(calls))
    result = adapter().health()
    assert result["status"] == "ok"
    command, kwargs = calls[0]
    assert command == ["C:/platform-tools/adb.exe", "-s", "emulator-5554", "get-state"]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 5.0


def test_adb_parses_ui_nodes_and_hashes_screenshots(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", fake_run_factory(calls))
    instance = adapter()
    state = instance.observe_state()
    assert state["foreground_app"] == "com.example.notes"
    assert state["source"] == "uiautomator"
    assert state["quality"] == "high"
    assert state["state_version"].startswith("v1:")
    assert state["device_fingerprint"]
    search = next(node for node in state["nodes"] if node["resource_id"] == "field-search")
    assert search["editable"] is True
    assert search["text_length"] == 5
    assert "hello" not in str(state)  # text is never exposed

    screenshot = instance.execute("device.screenshot", {})
    assert screenshot.status == "succeeded"
    assert screenshot.output["redacted"] is True
    assert screenshot.output["mime_type"] == "image/png"
    assert screenshot.output["screenshot_sha256"]
    assert screenshot.evidence_refs == [f"sha256:{screenshot.output['screenshot_sha256']}"]


def test_adb_refuses_non_allowlisted_apps_and_unsafe_text(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", fake_run_factory(calls))
    instance = adapter()
    rejected = instance.execute("app.launch", {"app_id": "com.evil.app"})
    assert rejected.status == "rejected"
    assert rejected.reason == "app_not_allowlisted"
    assert not any("monkey" in " ".join(call[0]) for call in calls)

    with pytest.raises(AdapterError):
        instance.execute("ui.type_text", {"target_ref": "field-search", "text": "a; rm -rf /"})


def test_adb_rejects_password_control_and_does_not_type(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", fake_run_factory(calls))
    result = adapter().execute("ui.type_text", {"target_ref": "field-password", "text": "1234"})
    assert result.status == "rejected"
    assert result.reason == "sensitive_control_blocked"
    assert not any("input text" in " ".join(call[0]) for call in calls)


def test_adb_unknown_target_fails_closed(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", fake_run_factory(calls))
    result = adapter().execute("ui.type_text", {"target_ref": "missing", "text": "hello"})
    assert result.status == "rejected"
    assert result.reason == "target_unverified"


def test_adb_timeout_is_uncertain(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(AdapterTimeout):
        adapter().observe_state()


def test_invalid_bounds_and_serial_are_rejected():
    with pytest.raises(ValueError):
        AndroidAdbAdapter(AdbSettings(adb_path="adb", serial="bad serial; rm",
                                      allowed_apps=frozenset()))
    instance = adapter()
    with pytest.raises(AdapterError):
        instance._center([10, 10, 5, 5])


def test_discovery_reports_unauthorized_and_offline(monkeypatch):
    from device_gateway.adapters import android_adb

    def fake_run(command, **kwargs):
        return FakeCompleted(stdout=(
            b"List of devices attached\n"
            b"emulator-5554\tdevice\n"
            b"emulator-5556\tunauthorized\n"
            b"emulator-5558\toffline\n"
        ))

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(android_adb, "shutil", type("S", (), {"which": staticmethod(lambda _: True)}))
    devices = android_adb.discover_devices("adb")
    assert [item["state"] for item in devices] == ["device", "unauthorized", "offline"]
    assert devices[1]["authorized"] is False
