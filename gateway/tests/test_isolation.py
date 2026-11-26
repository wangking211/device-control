import time

import pytest
from device_gateway.isolation import ProcessRunner, RunnerTimeout


def runner(**config):
    values = {
        "allowed_apps": ["com.example.notes"],
        "device_fingerprint": "test-device-fingerprint",
    }
    values.update(config)
    return ProcessRunner("fake", values, allowed_apps=frozenset({"com.example.notes"}))


def test_hard_timeout_kills_hung_adapter_and_next_call_works():
    hung = runner(hang=True)
    started = time.monotonic()
    with pytest.raises(RunnerTimeout):
        hung.execute("device.observe", {}, 0.4)
    elapsed = time.monotonic() - started
    assert elapsed < 5.0

    healthy = runner()
    state = healthy.observe_state(timeout_seconds=5.0)
    assert state["state_hash"]
    assert state["device_fingerprint"] == "test-device-fingerprint"
    assert state["nodes"]


def test_adapter_exception_is_mapped_to_adapter_error():
    failing = runner(fail_next="driver exploded")
    with pytest.raises(Exception) as exc:
        failing.execute("app.launch", {"app_id": "com.example.notes"}, 5.0)
    assert "driver exploded" in str(exc.value)
