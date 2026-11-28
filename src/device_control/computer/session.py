"""Windows interactive-session detection without hidden-desktop control."""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass

DESKTOP_READOBJECTS = 0x0001
DESKTOP_SWITCHDESKTOP = 0x0100


@dataclass(frozen=True)
class SessionInfo:
    state: str  # unlocked | locked | logged_out | unavailable
    interactive: bool
    session_id: int | None = None
    foreground_window: int | None = None

    def allows_ui(self) -> bool:
        return self.state == "unlocked" and self.interactive


def detect_session() -> SessionInfo:
    if sys.platform != "win32":
        return SessionInfo(state="unavailable", interactive=False)
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        desktop = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP)
        if not desktop:
            # No input desktop: locked, secure desktop (UAC/login), or disconnected.
            return SessionInfo(state="locked", interactive=False)
        user32.CloseDesktop(desktop)
        session_id = int(kernel32.WTSGetActiveConsoleSessionId())
        if session_id in {-1, 0xFFFFFFFF}:
            return SessionInfo(state="logged_out", interactive=False)
        foreground = int(user32.GetForegroundWindow())
        return SessionInfo(state="unlocked", interactive=True,
                           session_id=session_id, foreground_window=foreground or None)
    except (AttributeError, OSError):
        return SessionInfo(state="unavailable", interactive=False)


def local_takeover_requested(path: str | None) -> bool:
    if not path:
        return False
    try:
        return os.path.isfile(path)
    except OSError:
        return True


__all__ = ["SessionInfo", "detect_session", "local_takeover_requested"]
