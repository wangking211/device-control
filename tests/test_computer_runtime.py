"""Windows Computer Control runtime, contracts and redaction tests.

These are deterministic provider-level tests. Live Windows UIA/Playwright and a
real interactive desktop are not exercised here.
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest
from PIL import Image

from device_control.computer.contracts import (
    ComputerAction,
    ComputerActionError,
    ComputerResult,
    redact_value,
)
from device_control.computer.ledger import ComputerRunLedger, LedgerCorrupt, LedgerEntry
from device_control.computer.manifest import (
    CAPABILITY_IDS,
    EXTERNAL_SIDE_EFFECT_CAPABILITIES,
    SHELL_CAPABILITIES,
    manifest_document,
)
from device_control.computer.providers.base import (
    ProviderEvidence,
    ProviderExecution,
    ProviderHealth,
)
from device_control.computer.redaction import redact_image
from device_control.computer.runtime import ComputerRuntime
from device_control.computer.session import SessionInfo


class FakeProvider:
    provider_id = "fake"

    def __init__(self, *, raises: bool = False) -> None:
        self.raises = raises
        self.calls = 0
        self.observations = 0

    def health(self) -> ProviderHealth:
        return ProviderHealth("ok", "fake", "1.0.0", capabilities=tuple(CAPABILITY_IDS))

    def observe(self, action):
        self.observations += 1
        raise NotImplementedError

    def execute(self, action):
        self.calls += 1
        if self.raises:
            raise RuntimeError("provider boom")
        return ProviderExecution(
            ComputerResult(status="succeeded", provider_status="ok",
                           verification={"verified": True, "method": "fake"},
                           output={"ok": True}),
            [ProviderEvidence("screenshot", "image/png", b"png-bytes")],
        )

    def cancel(self, command_id):
        return {"accepted": False, "too_late": True}

    def close(self):
        return None


class FakeClient:
    gateway_id = "computer-gw-1"

    def __init__(self, commands):
        self.commands = commands
        self.results = []
        self.progresses = []
        self.evidence_uploads = []

    def pull(self, limit=10):
        return list(self.commands)

    def progress(self, command_id, status):
        self.progresses.append((command_id, status))
        return {}

    def result(self, command_id, payload):
        self.results.append((command_id, payload))
        return {}

    def upload_evidence(self, command_id, data, **kwargs):
        self.evidence_uploads.append((command_id, data, kwargs))
        return {"evidence_id": "evd_1"}


def envelope(**overrides):
    payload = {
        "protocol_version": "v1",
        "command_id": "cmd-1",
        "tenant_ref": "tenant-a",
        "gateway_id": "computer-gw-1",
        "endpoint_id": "pc-endpoint-1",
        "device_id": "pc-1",
        "task_ref": "task-1",
        "run_ref": "run-1",
        "capability_id": "computer.observe",
        "capability_version": "1.0.0",
        "operation": "observe",
        "parameters": {},
        "idempotency_key": "task-1:run-1:computer.observe",
        "deadline": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    payload.update(overrides)
    return payload


def runtime(tmp_path, *, commands=None, provider=None, session="unlocked", pause=None):
    provider = provider or FakeProvider()
    client = FakeClient(commands or [envelope()])
    instance = ComputerRuntime(
        client=client,
        desktop_provider=provider,
        tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1",
        device_id="pc-1",
        gateway_id="computer-gw-1",
        ledger=ComputerRunLedger(tmp_path / "ledger.json"),
        pause_path=str(pause) if pause else None,
        session_probe=lambda: SessionInfo(state=session, interactive=session == "unlocked"),
    )
    return instance, client, provider


def test_manifest_has_no_shell_and_marks_external_side_effects():
    document = manifest_document()
    ids = {item["id"] for item in document["capabilities"]}
    assert set(CAPABILITY_IDS) == ids
    assert SHELL_CAPABILITIES == frozenset()
    assert "browser.submit" in EXTERNAL_SIDE_EFFECT_CAPABILITIES
    risk = {item["id"]: item["risk_tier"] for item in document["capabilities"]}
    assert risk["computer.observe"] == "read"
    assert risk["browser.submit"] == "write"


def test_action_validation_and_fingerprint():
    action = ComputerAction.from_envelope(envelope())
    assert action.fingerprint() == ComputerAction.from_envelope(envelope()).fingerprint()
    changed = ComputerAction.from_envelope(envelope(parameters={"include_tree": True}))
    assert action.fingerprint() != changed.fingerprint()
    with pytest.raises(ComputerActionError):
        ComputerAction.from_envelope(envelope(capability_id=""))


def test_redaction_masks_sensitive_keys_and_pixels():
    redacted = redact_value({"password": "sentinel", "nested": {"token": "abc"},
                             "text": "authorization: bearer x"})
    assert "sentinel" not in str(redacted)
    assert "abc" not in str(redacted)
    assert "bearer" not in str(redacted).lower()
    image = Image.new("RGB", (20, 20), "white")
    content = redact_image(image, [[2, 2, 10, 10]])
    restored = Image.open(io.BytesIO(content))
    assert restored.getpixel((5, 5)) == (0, 0, 0)
    assert restored.getpixel((15, 15)) == (255, 255, 255)


def test_locked_session_and_pause_reject_without_provider_call(tmp_path):
    instance, client, provider = runtime(tmp_path, session="locked")
    instance.run_once()
    assert provider.calls == 0
    assert client.results[0][1]["status"] == "rejected"
    assert client.results[0][1]["reason"] == "session_locked"

    pause = tmp_path / "takeover"
    pause.write_text("1", encoding="utf-8")
    instance, client, provider = runtime(tmp_path, pause=pause)
    instance.run_once()
    assert provider.calls == 0
    assert client.results[0][1]["reason"] == "local_takeover"


def test_binding_mismatch_and_shell_are_rejected(tmp_path):
    instance, client, provider = runtime(tmp_path, commands=[
        envelope(tenant_ref="tenant-b"),
        envelope(capability_id="computer.shell.exec"),
    ])
    instance.run_once()
    assert provider.calls == 0
    assert [item[1]["reason"] for item in client.results] == [
        "binding_mismatch", "capability_not_allowlisted",
    ]


def test_success_uploads_redacted_evidence_and_reports_terminal(tmp_path):
    instance, client, provider = runtime(tmp_path)
    instance.run_once()
    assert provider.calls == 1
    assert client.evidence_uploads[0][0] == "cmd-1"
    result = client.results[0][1]
    assert result["status"] == "succeeded"
    assert result["evidence_refs"] == ["evd_1"]
    assert result["execution" if "execution" in result else "output"] == {"ok": True}
    assert ("cmd-1", "accepted") in client.progresses
    assert ("cmd-1", "executing") in client.progresses


def test_duplicate_delivery_reports_recorded_result_without_second_action(tmp_path):
    instance, client, provider = runtime(tmp_path)
    instance.run_once()
    instance.run_once()
    assert provider.calls == 1
    assert len(client.results) == 2
    assert client.results[0][1]["status"] == client.results[1][1]["status"] == "succeeded"


def test_crash_after_dispatch_is_unknown_and_never_replayed(tmp_path):
    ledger = ComputerRunLedger(tmp_path / "ledger.json")
    action = ComputerAction.from_envelope(envelope())
    ledger.record(LedgerEntry(
        schema="dc.computer-ledger/v1", tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", idempotency_key=action.idempotency_key,
        fingerprint=action.fingerprint(), phase="executing", command_id="cmd-1",
    ))
    client = FakeClient([envelope()])
    provider = FakeProvider()
    instance = ComputerRuntime(
        client=client, desktop_provider=provider, tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", device_id="pc-1", gateway_id="computer-gw-1",
        ledger=ledger,
        session_probe=lambda: SessionInfo(state="unlocked", interactive=True),
    )
    instance.run_once()
    assert provider.calls == 0
    assert client.results[0][1]["status"] == "uncertain"
    assert client.results[0][1]["output"] == {} or client.results[0][1]["reason"] == "unknown_after_dispatch"


def test_provider_exception_marks_unknown_and_is_not_replayed(tmp_path):
    provider = FakeProvider(raises=True)
    instance, client, _ = runtime(tmp_path, provider=provider)
    instance.run_once()
    assert provider.calls == 1
    assert client.results[0][1]["status"] == "uncertain"
    instance.run_once()
    assert provider.calls == 1
    assert client.results[1][1]["status"] == "uncertain"


def test_ledger_persists_and_corruption_fails_closed(tmp_path):
    path = tmp_path / "ledger.json"
    ledger = ComputerRunLedger(path)
    action = ComputerAction.from_envelope(envelope())
    ledger.record(LedgerEntry(
        schema="dc.computer-ledger/v1", tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", idempotency_key=action.idempotency_key,
        fingerprint=action.fingerprint(), phase="completed", command_id="cmd-1",
        result={"status": "succeeded"},
    ))
    restored = ComputerRunLedger(path).get(action.ledger_key())
    assert restored is not None and restored.command_id == "cmd-1"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(LedgerCorrupt):
        ComputerRunLedger(path)


def test_health_reports_session_and_providers(tmp_path):
    instance, _, _ = runtime(tmp_path)
    health = instance.health()
    assert health["session"] == "unlocked"
    assert health["desktop_provider"] == "ok"
    assert health["paused"] is False

def test_desktop_mutex_serializes_two_actions(tmp_path):
    import threading
    import time

    class SlowProvider(FakeProvider):
        def __init__(self):
            super().__init__()
            self.active = 0
            self.max_active = 0
            self.guard = threading.Lock()

        def execute(self, action):
            with self.guard:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            time.sleep(0.05)
            try:
                return super().execute(action)
            finally:
                with self.guard:
                    self.active -= 1

    provider = SlowProvider()
    client = FakeClient([])
    instance = ComputerRuntime(
        client=client, desktop_provider=provider, tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", device_id="pc-1", gateway_id="computer-gw-1",
        ledger=ComputerRunLedger(tmp_path / "ledger.json"),
        session_probe=lambda: SessionInfo(state="unlocked", interactive=True),
    )
    threads = [
        threading.Thread(target=instance._execute, args=(envelope(
            command_id=f"cmd-{index}", idempotency_key=f"task-1:run-1:key-{index}",
        ),))
        for index in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert provider.max_active == 1
    assert len(client.results) == 2
