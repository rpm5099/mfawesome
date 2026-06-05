from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from textual.app import App

logger = logging.getLogger("mfa.clipboard")


def copy(app: App, text: str) -> tuple[bool, str]:
    """Copy text to clipboard. Tries Textual's OSC 52 first (works over SSH/tmux/PuTTY),
    falls back to pyperclip (local clipboard via xclip/xsel/Win32/pbcopy).
    Returns (success, method) where method is "osc52", "pyperclip", or "failed".
    """
    try:
        app.copy_to_clipboard(text)
        return True, "osc52"
    except Exception as e:
        logger.debug(f"OSC 52 clipboard failed: {e!r}")

    try:
        import pyperclip

        pyperclip.copy(text)
        return True, "pyperclip"
    except Exception as e:
        logger.debug(f"pyperclip clipboard failed: {e!r}")

    return False, "failed"
