"""Adapter isolation with a hard, killable timeout.

Production adapters run in a short-lived child process per call. A hung
adapter is terminated (and killed if necessary) and a fresh process is created
for the next call. A killed action may already have reached the device, so the
worker treats it as uncertain and never replays a non-idempotent command.
"""

from __future__ import annotations

import dataclasses
import multiprocessing as mp
from typing import Any, Protocol

from .adapters.base import ActionResult, AdapterError, AdapterTimeout, DeviceAdapter


class RunnerTimeout(AdapterTimeout):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class Runner(Protocol):
    adapter_id: str
    version: str
    allowed_apps: frozenset[str]

    def execute(self, capability_id: str, parameters: dict[str, Any],
                timeout_seconds: float) -> ActionResult:
        ...

    def observe_state(self, timeout_seconds: float = 10.0) -> dict[str, Any]:
        ...

    def health(self) -> dict[str, Any]:
        ...

    def close(self) -> None:
        ...


class DirectRunner:
    """In-process runner for tests, fake adapters and the legacy null adapter."""

    def __init__(self, adapter: DeviceAdapter) -> None:
        self.adapter = adapter
        self.adapter_id = getattr(adapter, "adapter_id", "unknown")
        self.version = getattr(adapter, "version", "0.0.0")
        self.allowed_apps = frozenset(getattr(adapter, "allowed_apps", frozenset()))

    def execute(self, capability_id: str, parameters: dict[str, Any],
                timeout_seconds: float) -> ActionResult:
        return self.adapter.execute(capability_id, parameters)

    def observe_state(self, timeout_seconds: float = 10.0) -> dict[str, Any]:
        return self.adapter.observe_state()

    def health(self) -> dict[str, Any]:
        return self.adapter.health()

    def close(self) -> None:
        self.adapter.close()


class ProcessRunner:
    """One child process per call; hard terminate/kill on timeout."""

    def __init__(self, adapter_kind: str, config: dict[str, Any],
                 allowed_apps: frozenset[str] = frozenset()) -> None:
        self.adapter_kind = adapter_kind
        self.config = dict(config)
        self.allowed_apps = allowed_apps
        self.adapter_id = f"{adapter_kind}-isolated"
        self.version = "1.1.0"
        self._context = mp.get_context("spawn")

    def execute(self, capability_id: str, parameters: dict[str, Any],
                timeout_seconds: float) -> ActionResult:
        value = self._call("execute", {
            "capability_id": capability_id,
            "parameters": parameters,
        }, timeout_seconds, executed=True)
        return ActionResult(**value)

    def observe_state(self, timeout_seconds: float = 10.0) -> dict[str, Any]:
        return self._call("observe_state", {}, timeout_seconds, executed=False)

    def health(self) -> dict[str, Any]:
        try:
            return self._call("health", {}, 5.0, executed=False)
        except (AdapterError, RunnerTimeout) as exc:
            return {"status": "unavailable", "reason": exc.error_class}

    def close(self) -> None:
        return None

    def _call(self, action: str, payload: dict[str, Any], timeout_seconds: float,
              *, executed: bool) -> Any:
        parent, child = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_child_entry,
            args=(self.adapter_kind, self.config, action, payload, child),
            daemon=True,
        )
        process.start()
        child.close()
        if not parent.poll(max(0.1, timeout_seconds)):
            process.terminate()
            process.join(timeout=1.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)
            parent.close()
            raise RunnerTimeout(
                f"adapter {action} exceeded {timeout_seconds}s and was terminated"
            )
        try:
            status, body = parent.recv()
        finally:
            parent.close()
            process.join(timeout=2.0)
            if process.is_alive():
                process.kill()
        if status == "ok":
            return body
        raise AdapterError(
            str(body.get("message") or "adapter failed"),
            error_class=str(body.get("error_class") or "adapter"),
            uncertain=bool(body.get("uncertain")),
            retryable=bool(body.get("retryable")),
        )


def _child_entry(adapter_kind: str, config: dict[str, Any], action: str,
                 payload: dict[str, Any], connection: Any) -> None:
    try:
        adapter = _build_adapter(adapter_kind, config)
        if action == "execute":
            result = adapter.execute(payload["capability_id"], payload["parameters"])
            connection.send(("ok", dataclasses.asdict(result)))
        elif action == "observe_state":
            connection.send(("ok", adapter.observe_state()))
        elif action == "health":
            connection.send(("ok", adapter.health()))
        else:  # pragma: no cover - defensive
            connection.send(("error", {"message": "unknown action", "error_class": "validation"}))
    except AdapterError as exc:
        connection.send(("error", {
            "message": str(exc),
            "error_class": exc.error_class,
            "uncertain": exc.uncertain,
            "retryable": exc.retryable,
        }))
    except Exception as exc:  # noqa: BLE001 - isolate adapter crashes
        connection.send(("error", {
            "message": f"{type(exc).__name__}: {exc}",
            "error_class": "adapter",
            "uncertain": action == "execute",
            "retryable": False,
        }))
    finally:
        connection.close()


def _build_adapter(adapter_kind: str, config: dict[str, Any]) -> DeviceAdapter:
    if adapter_kind == "android":
        from .adapters.android_adb import AdbSettings, AndroidAdbAdapter

        return AndroidAdbAdapter(AdbSettings(
            adb_path=str(config.get("adb_path") or ""),
            serial=str(config.get("serial") or ""),
            allowed_apps=frozenset(config.get("allowed_apps") or ()),
            command_timeout_seconds=float(config.get("command_timeout_seconds") or 15.0),
        ))
    if adapter_kind == "fake":
        from .adapters.fake import FakeAndroidAdapter

        adapter = FakeAndroidAdapter(
            allowed_apps=set(config.get("allowed_apps") or ()) or None,
            device_fingerprint=str(config.get("device_fingerprint") or "fake-device-fingerprint"),
        )
        if config.get("hang"):
            adapter.hang = True
        if config.get("fail_next"):
            adapter.fail_next = str(config["fail_next"])
        return adapter
    from .adapters.base import NullAdapter

    return NullAdapter()
