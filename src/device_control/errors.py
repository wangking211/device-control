"""Typed API errors mapped onto the DC-002 error semantics."""

from __future__ import annotations

from typing import Any


class DeviceControlError(Exception):
    """An error with an HTTP status, a stable code and safe detail."""

    def __init__(self, status_code: int, code: str, *, detail: Any = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.headers = headers or {}

    def envelope(self) -> dict[str, Any]:
        body: dict[str, Any] = {"code": self.code}
        if self.detail is not None:
            body["detail"] = self.detail
        return body


def unauthenticated(code: str = "unauthenticated") -> DeviceControlError:
    return DeviceControlError(401, code)


def forbidden(code: str = "insufficient_scope") -> DeviceControlError:
    return DeviceControlError(403, code)


def hidden() -> DeviceControlError:
    """Tenant-scoped resources are indistinguishable from missing ones."""

    return DeviceControlError(404, "not_found")


def conflict(code: str, detail: Any = None) -> DeviceControlError:
    return DeviceControlError(409, code, detail=detail)


def invalid(code: str, detail: Any = None) -> DeviceControlError:
    return DeviceControlError(422, code, detail=detail)


def rate_limited(retry_after_seconds: int = 1) -> DeviceControlError:
    return DeviceControlError(429, "rate_limited",
                             headers={"Retry-After": str(max(1, retry_after_seconds))})


def dependency_unavailable(code: str = "identity_provider_unavailable") -> DeviceControlError:
    return DeviceControlError(503, code)
