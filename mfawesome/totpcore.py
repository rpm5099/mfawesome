"""Pure TOTP/HOTP calculation primitives. No display dependencies.

This module is imported by both totp.py (CLI / Rich display) and tui.py
(Textual UI). Keeping it dependency-free of display code prevents circular
imports.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import struct
from collections import namedtuple

from mfawesome.ntptime import CorrectedTime
from mfawesome.utils import b32decode, gettime

logger = logging.getLogger("mfa.totpcore")

NTPCT: CorrectedTime | None = None

TOTPCode = namedtuple("TOTPCode", ["code", "remaining", "untilvalid", "validtimestamp"])


def init(timeservers: list | None) -> None:
    """Initialize the module-level NTP-corrected time source."""
    global NTPCT
    NTPCT = CorrectedTime(timeservers)


def RemainingTime(period_offset: int = 0) -> float:
    return float(30.0 - (NTPCT.time % 30)) + (30.0 * period_offset)


def totpcalc(secret: str, period_offset: int = 0) -> tuple[str, float]:
    secret = secret.replace("\t", "")
    ts = NTPCT.time + (30.0 * period_offset)
    periodnum = int(ts / 30.0)
    key = b32decode(secret.upper())
    b = struct.pack(">q", int(periodnum))
    hm = hmac.HMAC(key, b, hashlib.sha1).digest()
    offset = hm[-1] & 0x0F
    truncatedHash = hm[offset : offset + 4]
    code = struct.unpack(">L", truncatedHash)[0]
    code &= 0x7FFFFFFF
    code %= 1000000
    final = str(code).zfill(6)
    return final, RemainingTime(period_offset)


def multitotpcalc(secret: str, codecount: int = 2) -> list:
    codes = []
    for i in range(codecount):
        code, remaining = totpcalc(secret, period_offset=i)
        uv = remaining - 30.0
        codes.append(TOTPCode(code, remaining, uv, gettime(NTPCT.time)))
    return codes


def hotpcalc(secret: str, count: int) -> tuple[str, int]:
    count = int(count)
    count += 1
    if count < 0:
        raise ValueError("HOTP count argument must be a positive integer")
    secret = secret.replace("\t", "")
    key = b32decode(secret.upper())
    b = struct.pack(">q", int(count))
    hm = hmac.HMAC(key, b, hashlib.sha1).digest()
    offset = hm[-1] & 0x0F
    truncatedHash = hm[offset : offset + 4]
    code = struct.unpack(">L", truncatedHash)[0]
    code &= 0x7FFFFFFF
    code %= 1000000
    return str(code).zfill(6), count
