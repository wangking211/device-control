"""Adapter lifecycle, timeout and circuit breaker.

Adapters are installed by manifest, then explicitly enabled, configured,
authorized and activated. A failure opens the circuit and does not propagate to
the core. Production deployments should run the adapter in a separate worker
process; this manager also enforces a timeout at the call boundary so a hanging
coroutine cannot block the API thread indefinitely.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .manifest import AdapterManifest
from .spi import AdapterError, AdapterHealth, AdapterPlugin, PlatformConfig


class LifecycleError(RuntimeError):
    pass


class AdapterState(str, Enum):
    INSTALLED = "installed"
    ENABLED = "enabled"
    CONFIGURED = "configured"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    DISABLED = "disabled"
    FAILED = "failed"


@dataclass
class _Runtime:
    manifest: AdapterManifest
    factory: Callable[[], AdapterPlugin]
    plugin: AdapterPlugin | None = None
    config: PlatformConfig | None = None
    state: AdapterState = AdapterState.INSTALLED
    failures: int = 0
    opened_at: float | None = None
    last_error: str | None = None
    limits: dict[str, Any] = field(default_factory=dict)


class AdapterLifecycleManager:
    def __init__(self, *, timeout_seconds: float = 10.0, failure_threshold: int = 3,
                 circuit_seconds: float = 30.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.failure_threshold = failure_threshold
        self.circuit_seconds = circuit_seconds
        self._runtimes: dict[str, _Runtime] = {}
        self._lock = threading.Lock()

    def install(self, manifest: AdapterManifest,
                factory: Callable[[], AdapterPlugin]) -> None:
        errors = manifest.validate()
        if errors:
            raise LifecycleError("invalid manifest: " + "; ".join(errors))
        with self._lock:
            if manifest.adapter_id in self._runtimes:
                raise LifecycleError("adapter already installed")
            self._runtimes[manifest.adapter_id] = _Runtime(manifest=manifest, factory=factory)

    def enable(self, adapter_id: str) -> None:
        self._require(adapter_id).state = AdapterState.ENABLED

    def configure(self, adapter_id: str, config: PlatformConfig) -> None:
        runtime = self._require(adapter_id)
        plugin = runtime.plugin or runtime.factory()
        runtime.plugin = plugin
        errors = plugin.validate_config(config)
        if errors:
            runtime.state = AdapterState.FAILED
            runtime.last_error = "; ".join(errors)
            raise LifecycleError(runtime.last_error)
        runtime.config = config
        runtime.state = AdapterState.CONFIGURED

    def authorize(self, adapter_id: str) -> None:
        runtime = self._require(adapter_id)
        if runtime.state not in {AdapterState.CONFIGURED, AdapterState.AUTHORIZED}:
            raise LifecycleError("adapter must be configured before authorize")
        runtime.state = AdapterState.AUTHORIZED

    def test(self, adapter_id: str) -> AdapterHealth:
        return self._call(adapter_id, lambda plugin: plugin.health())

    def connect(self, adapter_id: str, resolve_secret: Callable[[str], str]) -> AdapterHealth:
        runtime = self._require(adapter_id)
        if runtime.state not in {AdapterState.AUTHORIZED, AdapterState.CONFIGURED}:
            raise LifecycleError("adapter is not authorized")
        if runtime.config is None:
            raise LifecycleError("adapter is not configured")
        adapter_config = runtime.config
        self._call(adapter_id, lambda plugin: plugin.connect(adapter_config, resolve_secret))
        runtime.state = AdapterState.ACTIVE
        return self._call(adapter_id, lambda plugin: plugin.health())

    def discover(self, adapter_id: str, cursor: str | None = None,
                 filters: dict[str, Any] | None = None):
        return self._call(adapter_id, lambda plugin: plugin.discover(cursor, filters))

    def execute(self, adapter_id: str, command: dict[str, Any]):
        return self._call(adapter_id, lambda plugin: plugin.execute(command))

    def disable(self, adapter_id: str) -> None:
        runtime = self._require(adapter_id)
        if runtime.plugin is not None:
            try:
                self._call(adapter_id, lambda plugin: plugin.disconnect())
            except Exception as exc:  # noqa: BLE001 - disabling must always complete
                runtime.last_error = type(exc).__name__
        runtime.state = AdapterState.DISABLED

    def uninstall(self, adapter_id: str) -> None:
        self.disable(adapter_id)
        with self._lock:
            self._runtimes.pop(adapter_id, None)

    def state(self, adapter_id: str) -> AdapterState:
        return self._require(adapter_id).state

    # -- internals ------------------------------------------------------

    def _require(self, adapter_id: str) -> _Runtime:
        with self._lock:
            runtime = self._runtimes.get(adapter_id)
        if runtime is None:
            raise LifecycleError("adapter not installed")
        return runtime

    def _call(self, adapter_id: str, action: Callable[[AdapterPlugin], Any]) -> Any:
        runtime = self._require(adapter_id)
        if runtime.plugin is None:
            raise LifecycleError("adapter plugin is not constructed")
        plugin = runtime.plugin
        if runtime.opened_at is not None:
            if time.monotonic() - runtime.opened_at < self.circuit_seconds:
                raise AdapterError("circuit_open", "adapter circuit is open")
            runtime.opened_at = None
            runtime.failures = 0
        result: list[Any] = []
        failure: list[BaseException] = []

        def target() -> None:
            try:
                result.append(action(plugin))
            except BaseException as exc:  # noqa: BLE001 - isolate plugin failure
                failure.append(exc)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(self.timeout_seconds)
        if thread.is_alive():
            runtime.failures += 1
            runtime.last_error = "adapter_timeout"
            self._maybe_open(runtime)
            raise AdapterError("adapter_timeout", "adapter call exceeded timeout")
        if failure:
            runtime.failures += 1
            runtime.last_error = type(failure[0]).__name__
            self._maybe_open(runtime)
            if isinstance(failure[0], AdapterError):
                raise failure[0]
            raise AdapterError("adapter_failure", str(failure[0])) from failure[0]
        runtime.failures = 0
        return result[0]

    def _maybe_open(self, runtime: _Runtime) -> None:
        runtime.state = AdapterState.FAILED
        if runtime.failures >= self.failure_threshold:
            runtime.opened_at = time.monotonic()
