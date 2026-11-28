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
        schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", idempotency_key=action.idempotency_key,
        task_ref=str(action.task_ref), run_ref=str(action.run_ref),
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
        schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", idempotency_key=action.idempotency_key,
        task_ref=str(action.task_ref), run_ref=str(action.run_ref),
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

def test_same_idempotency_key_different_task_or_run_is_distinct(tmp_path):
    ledger = ComputerRunLedger(tmp_path / "ledger.json")
    base = dict(schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
                endpoint_id="pc-endpoint-1", idempotency_key="same-key",
                fingerprint="fp", phase="unknown", command_id="cmd-1")
    ledger.record(LedgerEntry(**base, task_ref="task-1", run_ref="run-1"))
    ledger.record(LedgerEntry(**base, task_ref="task-2", run_ref="run-1"))
    ledger.record(LedgerEntry(**base, task_ref="task-1", run_ref="run-2"))
    assert len(ledger.unresolved()) == 3


def test_ledger_never_evicts_unknown_and_fails_closed_at_capacity(tmp_path, monkeypatch):
    import device_control.computer.ledger as ledger_module

    monkeypatch.setattr(ledger_module, "MAX_ENTRIES", 2)
    ledger = ComputerRunLedger(tmp_path / "ledger.json")
    for index in range(2):
        ledger.record(LedgerEntry(
            schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
            endpoint_id="pc-endpoint-1", idempotency_key=f"key-{index}",
            fingerprint="fp", phase="unknown", command_id=f"cmd-{index}",
            task_ref="task-1", run_ref="run-1",
        ))
    assert len(ledger.unresolved()) == 2
    with pytest.raises(ledger_module.LedgerCapacity):
        ledger.record(LedgerEntry(
            schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
            endpoint_id="pc-endpoint-1", idempotency_key="new",
            fingerprint="fp", phase="executing", command_id="cmd-new",
            task_ref="task-1", run_ref="run-1",
        ))
    assert len(ledger.unresolved()) == 2


def test_external_side_effect_requires_approval_ref(tmp_path):
    instance, client, provider = runtime(tmp_path, commands=[
        envelope(capability_id="browser.submit", operation="submit",
                 parameters={"locator": {"role": "button", "name": "Send"},
                             "postcondition": {"kind": "text_contains", "value": "sent"}}),
    ])
    instance.run_once()
    assert provider.calls == 0
    assert client.results[0][1]["reason"] == "approval_required"


def test_reconcile_unknown_is_observation_only(tmp_path):
    class ObservingProvider(FakeProvider):
        def observe(self, action):
            self.observations += 1
            from device_control.computer.contracts import ComputerObservation
            return ComputerObservation(session_state="unlocked", uia_tree={"name": "ok"})

    provider = ObservingProvider()
    instance, client, _ = runtime(tmp_path, provider=provider)
    action = ComputerAction.from_envelope(envelope())
    observation = instance.reconcile_unknown(action)
    assert observation["uia_tree"]["name"] == "ok"
    assert provider.observations == 1
    assert provider.calls == 0

class _FakeLocator:
    def __init__(self, *, count_value=1, text="", visible=True):
        self._count = count_value
        self._text = text
        self._visible = visible
        self.clicks = 0
        self.value = ""

    def count(self):
        return self._count

    def click(self, **kwargs):
        self.clicks += 1

    def fill(self, value, **kwargs):
        self.value = value

    def input_value(self, **kwargs):
        return self.value

    def inner_text(self, **kwargs):
        return self._text

    def is_visible(self):
        return self._visible


class _FakePage:
    def __init__(self, *, url="https://app.example/form", body="", after_text=None):
        self.url = url
        self.body = body
        self.after_text = after_text
        self.locator_calls = []

    def _element(self):
        return _FakeLocator(text=self.after_text if self.after_text is not None else self.body)

    def locator(self, selector):
        self.locator_calls.append(selector)
        return self._element()

    def get_by_role(self, role, name=None):
        return self._element()

    def get_by_label(self, label):
        return self._element()

    def get_by_text(self, text):
        return self._element()

    def get_by_placeholder(self, text):
        return self._element()

    def title(self):
        return "Test"


def _browser_action(parameters):
    return ComputerAction.from_envelope(envelope(
        capability_id="browser.submit", operation="submit", parameters=parameters,
    ))


def test_browser_submit_requires_postcondition_and_click_alone_is_not_success(tmp_path):
    from device_control.computer.providers.playwright import PlaywrightProvider

    provider = PlaywrightProvider()
    provider._page = _FakePage(body="no receipt")
    missing = provider._submit(_browser_action({
        "locator": {"role": "button", "name": "Send"},
    }))
    assert missing.result.status == "failed"
    assert missing.result.error_code == "postcondition_required"

    unverified = provider._submit(_browser_action({
        "locator": {"role": "button", "name": "Send"},
        "postcondition": {"kind": "text_contains", "value": "sent"},
    }))
    assert unverified.result.status == "executed_unverified"
    assert unverified.result.verification["verified"] is False


def test_browser_submit_with_receipt_postcondition_succeeds(tmp_path):
    from device_control.computer.providers.playwright import PlaywrightProvider

    provider = PlaywrightProvider()
    provider._page = _FakePage(body="submitted receipt RCPT-123")
    result = provider._submit(_browser_action({
        "locator": {"role": "button", "name": "Send"},
        "postcondition": {"kind": "receipt_id", "value": "RCPT-123"},
    }))
    assert result.result.status == "succeeded"
    assert result.result.verification["verified"] is True


def test_navigation_wrong_expected_path_is_not_verified():
    from device_control.computer.providers.playwright import PlaywrightProvider

    provider = PlaywrightProvider()
    page = _FakePage(url="https://app.example/other")
    page.goto = lambda *args, **kwargs: None
    provider._page = page
    result = provider._navigate(_browser_action({
        "url": "https://app.example/form",
        "expected_url_contains": "/form",
    }))
    assert result.result.status == "executed_unverified"

def _mutex_worker(started, release):
    from device_control.computer.session_mutex import DesktopMutex

    mutex = DesktopMutex(0)
    acquired = mutex.acquire(2.0)
    started.set()
    release.wait(5)
    if acquired:
        mutex.release()


def _ledger_worker(path, index, done):
    from device_control.computer.ledger import ComputerRunLedger, LedgerEntry

    ledger = ComputerRunLedger(path)
    ledger.record(LedgerEntry(
        schema="dc.computer-ledger/v2", tenant_ref="tenant-a",
        endpoint_id="pc-endpoint-1", idempotency_key=f"cross-{index}",
        fingerprint=f"fp-{index}", phase="unknown", command_id=f"cmd-{index}",
        task_ref="task-1", run_ref="run-1",
    ))
    done.set()


def test_desktop_mutex_is_cross_process_on_windows():
    import multiprocessing
    import sys

    if sys.platform != "win32":
        pytest.skip("Windows named mutex acceptance requires Windows")
    started = multiprocessing.Event()
    release = multiprocessing.Event()
    worker = multiprocessing.Process(target=_mutex_worker, args=(started, release))
    worker.start()
    try:
        assert started.wait(5)
        from device_control.computer.session_mutex import DesktopMutex

        assert DesktopMutex(0).acquire(0.2) is False
    finally:
        release.set()
        worker.join(5)


def test_ledger_cross_process_writes_do_not_lose_updates(tmp_path):
    import multiprocessing

    path = str(tmp_path / "ledger.json")
    done_a, done_b = multiprocessing.Event(), multiprocessing.Event()
    workers = [
        multiprocessing.Process(target=_ledger_worker, args=(path, 0, done_a)),
        multiprocessing.Process(target=_ledger_worker, args=(path, 1, done_b)),
    ]
    for worker in workers:
        worker.start()
    try:
        assert done_a.wait(10) and done_b.wait(10)
    finally:
        for worker in workers:
            worker.join(5)
    ledger = ComputerRunLedger(path)
    assert len(ledger.unresolved()) == 2

def test_evidence_upload_failure_does_not_replay_action(tmp_path):
    instance, client, provider = runtime(tmp_path)
    client.upload_evidence = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("disk full"))
    instance.run_once()
    assert provider.calls == 1
    assert client.results[0][1]["status"] == "succeeded"
    assert client.results[0][1]["evidence_refs"] == []
    instance.run_once()
    assert provider.calls == 1
