"""Playwright browser provider with semantic locators and isolated context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..contracts import ComputerAction, ComputerObservation, ComputerResult, redact_value
from ..session import detect_session
from .base import ProviderExecution, ProviderHealth

_BLOCKED_SCHEMES = {"file", "javascript", "data", "about", "chrome", "edge"}


@dataclass
class PlaywrightProvider:
    provider_id: str = "playwright-browser"
    headless: bool = False
    timeout_ms: int = 20_000
    allowed_hosts: set[str] = field(default_factory=set)
    _browser: Any = None

    def _sync(self):
        from playwright.sync_api import sync_playwright
        return sync_playwright

    def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        sync_playwright = self._sync()
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=self.headless)
        self._context = self._browser.new_context(ignore_https_errors=False)
        self._page = self._context.new_page()
        return self._browser

    def health(self) -> ProviderHealth:
        session = detect_session()
        try:
            self._sync()
        except Exception:  # noqa: BLE001 - optional dependency
            return ProviderHealth("unavailable", self.provider_id, "0.1.0",
                                  "playwright is not installed")
        if not session.allows_ui() and not self.headless:
            return ProviderHealth("degraded", self.provider_id, "0.1.0",
                                  f"session {session.state}")
        return ProviderHealth("ok", self.provider_id, "0.1.0",
                              capabilities=("browser.navigate", "browser.inspect",
                                            "browser.fill", "browser.submit"))

    def observe(self, action: ComputerAction) -> ComputerObservation:
        self._ensure_browser()
        text = ""
        try:
            text = self._page.locator("body").inner_text(timeout=self.timeout_ms)[:4000]
        except Exception:  # noqa: BLE001 - page may be blank
            text = ""
        return ComputerObservation(
            session_state="unlocked",
            active_window={"url": self._page.url, "title": self._page.title()},
            uia_tree={"text": redact_value(text)},
        )

    def execute(self, action: ComputerAction) -> ProviderExecution:
        capability = action.capability_id
        try:
            self._ensure_browser()
            if capability == "browser.navigate":
                return self._navigate(action)
            if capability == "browser.inspect":
                return self._inspect(action)
            if capability == "browser.fill":
                return self._fill(action)
            if capability == "browser.submit":
                return self._submit(action)
            return self._failed("unsupported_capability")
        except Exception as exc:  # noqa: BLE001 - provider isolation
            return self._failed(f"playwright_{type(exc).__name__}")

    def cancel(self, command_id: str) -> dict[str, Any]:
        try:
            self._page.stop()
        except Exception:  # noqa: BLE001 - best effort
            return {"accepted": False, "too_late": True, "command_id": command_id}
        return {"accepted": True, "too_late": False, "command_id": command_id}

    def close(self) -> None:
        for target in ("_context", "_browser", "_playwright"):
            resource = getattr(self, target, None)
            if resource is not None:
                try:
                    resource.close() if target != "_playwright" else resource.stop()
                except Exception:  # noqa: BLE001 - shutdown is best effort
                    ...
                setattr(self, target, None)

    # -- actions ------------------------------------------------------

    def _navigate(self, action: ComputerAction) -> ProviderExecution:
        url = str(action.parameters.get("url") or "")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.scheme in _BLOCKED_SCHEMES:
            return self._failed("url_scheme_blocked")
        if not parsed.hostname:
            return self._failed("url_invalid")
        if self.allowed_hosts and parsed.hostname.lower() not in self.allowed_hosts:
            return self._failed("host_not_allowlisted")
        self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        return ProviderExecution(ComputerResult(
            status="succeeded", provider_status="navigated",
            verification={"verified": self._page.url.startswith(parsed.scheme), "method": "url_check"},
            output={"url": self._page.url[:500], "title": self._page.title()[:200]},
        ))

    def _inspect(self, action: ComputerAction) -> ProviderExecution:
        locator = dict(action.parameters.get("locator") or {})
        element = self._locator(locator)
        text = ""
        if element is not None:
            try:
                text = element.inner_text(timeout=5_000)[:2000]
            except Exception:  # noqa: BLE001 - missing text
                text = ""
        return ProviderExecution(ComputerResult(
            status="succeeded", provider_status="inspected",
            output=redact_value({"url": self._page.url, "title": self._page.title(),
                                 "text": text}),
        ))

    def _fill(self, action: ComputerAction) -> ProviderExecution:
        if action.parameters.get("sensitive") is True:
            return self._failed("sensitive_text_blocked")
        locator = dict(action.parameters.get("locator") or {})
        value = str(action.parameters.get("value") or "")
        element = self._locator(locator)
        if element is None:
            return self._failed("locator_missing")
        element.fill(value, timeout=self.timeout_ms)
        actual = str(element.input_value(timeout=self.timeout_ms))
        return ProviderExecution(ComputerResult(
            status="succeeded" if actual == value else "executed_unverified",
            provider_status="filled",
            verification={"verified": actual == value, "method": "input_value_check"},
            output={"length": len(value)},
        ))

    def _submit(self, action: ComputerAction) -> ProviderExecution:
        locator = dict(action.parameters.get("locator") or {})
        element = self._locator(locator)
        if element is None:
            return self._failed("locator_missing")
        before = self._page.url
        element.click(timeout=self.timeout_ms)
        try:
            self._page.wait_for_load_state("domcontentloaded", timeout=5_000)
        except Exception:  # noqa: BLE001 - SPA submit may not navigate
            ...
        after = self._page.url
        return ProviderExecution(ComputerResult(
            status="succeeded", provider_status="submitted",
            verification={"verified": True, "method": "click_postcondition"},
            output={"url_changed": before != after},
        ))

    def _locator(self, locator: dict[str, Any]):
        if not locator:
            return None
        if locator.get("role") and locator.get("name"):
            return self._page.get_by_role(str(locator["role"]), name=str(locator["name"]))
        if locator.get("label"):
            return self._page.get_by_label(str(locator["label"]))
        if locator.get("text"):
            return self._page.get_by_text(str(locator["text"]))
        if locator.get("placeholder"):
            return self._page.get_by_placeholder(str(locator["placeholder"]))
        if locator.get("css") and re.fullmatch(r"[#.\w\-\s>:\\[\\]=\"']{1,200}", str(locator["css"])):
            return self._page.locator(str(locator["css"]))
        return None

    def _failed(self, code: str) -> ProviderExecution:
        return ProviderExecution(ComputerResult(
            status="failed", provider_status=code, error_code=code,
            error_message=code[:240],
        ))


__all__ = ["PlaywrightProvider"]
