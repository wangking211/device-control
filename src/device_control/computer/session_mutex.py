"""OS-level desktop ownership lock for Computer Runtime.

Windows uses a session-scoped named mutex so independent Runtime processes
cannot drive the same interactive desktop concurrently. Non-Windows/test
environments fall back to a process-wide named lock only; that fallback is not
a substitute for Windows acceptance.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from contextlib import contextmanager
from typing import Iterator

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102

_PROCESS_FALLBACK = threading.Lock()


class DesktopMutex:
    def __init__(self, session_id: int | None, *, name: str = "MindOS.ComputerControl.Desktop") -> None:
        self.session_id = session_id or 0
        self.name = f"Local\\{name}.{self.session_id}"
        self._handle: int | None = None
        self._fallback = False

    def acquire(self, timeout_seconds: float = 2.0) -> bool:
        if sys.platform != "win32":
            # Process-local fallback only; not evidence for cross-process safety.
            self._fallback = True
            return _PROCESS_FALLBACK.acquire(timeout=max(0.0, timeout_seconds))
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, self.name)
        if not handle:
            return False
        result = kernel32.WaitForSingleObject(handle, int(max(0.0, timeout_seconds) * 1000))
        if result in {WAIT_OBJECT_0, WAIT_ABANDONED}:
            self._handle = handle
            return True
        kernel32.CloseHandle(handle)
        return False

    def release(self) -> None:
        if self._fallback:
            self._fallback = False
            try:
                _PROCESS_FALLBACK.release()
            except RuntimeError:
                pass
            return
        if self._handle is None:
            return
        kernel32 = ctypes.windll.kernel32
        kernel32.ReleaseMutex(self._handle)
        kernel32.CloseHandle(self._handle)
        self._handle = None

    @contextmanager
    def hold(self, timeout_seconds: float = 2.0) -> Iterator[bool]:
        acquired = self.acquire(timeout_seconds)
        try:
            yield acquired
        finally:
            if acquired:
                self.release()


__all__ = ["DesktopMutex"]
