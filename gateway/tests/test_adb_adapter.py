import subprocess

import pytest
from device_gateway.adapters.android_adb import AdbSettings, AndroidAdbAdapter
from device_gateway.adapters.base import AdapterError, AdapterTimeout


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
    )
    if overrides:
        settings = AdbSettings(**{**settings.__dict__, **overrides})
    return AndroidAdbAdapter(settings)


def test_adb_invocation_uses_argument_arrays_and_no_shell(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return FakeCompleted(stdout=b"device\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = adapter().health()
    assert result["status"] == "ok"
    command, kwargs = calls[0]
    assert command == ["C:/platform-tools/adb.exe", "-s", "emulator-5554", "get-state"]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 5.0


def test_adb_parses_foreground_app_and_hashes_screenshots(monkeypatch):
    raw_png = b"\x89PNG\r\nfake-frame"

    def fake_run(command, **kwargs):
        if "dumpsys" in command:
            return FakeCompleted(stdout=b"  mCurrentFocus=Window{abc u0 com.example.notes/com.example.NotesActivity}")
        return FakeCompleted(stdout=raw_png)

    monkeypatch.setattr(subprocess, "run", fake_run)
    instance = adapter()
    assert instance.observe_state()["foreground_app"] == "com.example.notes"
    screenshot = instance.execute("observe.screenshot", {})
    assert screenshot.status == "succeeded"
    assert screenshot.output["redacted"] is True
    assert screenshot.output["bytes"] == len(raw_png)
    assert screenshot.output["screenshot_sha256"]
    assert screenshot.evidence_refs == [f"sha256:{screenshot.output['screenshot_sha256']}"]


def test_adb_refuses_non_allowlisted_apps_and_unsafe_text(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    instance = adapter()
    rejected = instance.execute("app.launch", {"app_id": "com.evil.app"})
    assert rejected.status == "rejected"
    assert rejected.reason == "app_not_allowlisted"
    assert calls == []

    with pytest.raises(AdapterError):
        instance.execute("ui.type_text", {"target_ref": "field", "text": "a; rm -rf /"})
    assert calls == []


def test_adb_rejects_secret_fields_without_calling_device(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or FakeCompleted())
    result = adapter().execute("ui.type_text", {"target_ref": "pin", "text": "1234",
                                                "target_type": "otp"})
    assert result.status == "rejected"
    assert result.reason == "secret_field_blocked"
    assert calls == []


def test_adb_timeout_is_uncertain(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(AdapterTimeout):
        adapter().observe_state()


def test_invalid_bounds_and_serial_are_rejected():
    with pytest.raises(ValueError):
        AdbSettings(adb_path="adb", serial="bad serial; rm", allowed_apps=frozenset())
        AndroidAdbAdapter(AdbSettings(adb_path="adb", serial="bad serial; rm", allowed_apps=frozenset()))
    instance = adapter()
    with pytest.raises(AdapterError):
        instance._center([10, 10, 5, 5])


def test_discovery_is_bounded_to_operator_configuration(monkeypatch):
    from device_gateway.adapters import android_adb

    def fake_run(command, **kwargs):
        return FakeCompleted(stdout=b"List of devices attached\nemulator-5554\tdevice\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(android_adb, "shutil", type("S", (), {"which": staticmethod(lambda _: True)}))
    devices = android_adb.discover_devices("adb")
    assert devices == [{"serial": "emulator-5554", "state": "device", "description": ""}]
