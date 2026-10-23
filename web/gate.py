"""
Passcode gate for the welcome page: an 8-digit code, checked on the server, with a lockout.

This is a classroom "front door", not access control: it decides whether the
browser shows the app, while the JSON API itself stays open on loopback.
The code is compared as a SHA-256 digest in constant time, and five wrong codes
in a row lock the gate for 30 seconds.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from typing import Any, Dict, Optional

from blockchain_lite.interfaces import ValidationError

PASSCODE_LENGTH = 8
DEFAULT_PASSCODE = "12345678"
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 30.0


def _digest(code: str) -> bytes:
    return hashlib.sha256(("blockchain-lite|" + code).encode("utf-8")).digest()


def validate_passcode_format(code: Any) -> str:
    if not isinstance(code, str) or len(code) != PASSCODE_LENGTH or not code.isdigit():
        raise ValidationError(f"The passcode is exactly {PASSCODE_LENGTH} digits")
    return code


class PasscodeGate:
    def __init__(self, passcode: str = DEFAULT_PASSCODE, clock: Any = time.monotonic) -> None:
        self._digest = _digest(validate_passcode_format(passcode))
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._locked_until: Optional[float] = None
        self.is_default = passcode == DEFAULT_PASSCODE

    def check(self, code: Any) -> Dict[str, Any]:
        """{granted, attempts_left, locked_for}; raises ValidationError for a malformed code."""
        validate_passcode_format(code)
        with self._lock:
            now = self._clock()
            if self._locked_until is not None:
                if now < self._locked_until:
                    return {"granted": False, "attempts_left": 0, "locked_for": round(self._locked_until - now, 1)}
                self._locked_until = None
                self._failures = 0
            if hmac.compare_digest(_digest(code), self._digest):
                self._failures = 0
                return {"granted": True, "attempts_left": MAX_ATTEMPTS, "locked_for": 0}
            self._failures += 1
            left = MAX_ATTEMPTS - self._failures
            if left <= 0:
                self._locked_until = now + LOCKOUT_SECONDS
                return {"granted": False, "attempts_left": 0, "locked_for": LOCKOUT_SECONDS}
            return {"granted": False, "attempts_left": left, "locked_for": 0}
