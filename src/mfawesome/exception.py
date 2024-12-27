from __future__ import annotations

import os
import platform
import sys
from typing import TYPE_CHECKING

import cryptography.exceptions

EXCEPTIONTESTMODE = False

if TYPE_CHECKING:
    from collections.abc import Generator

Cryptography_Exceptions = (
    cryptography.exceptions.UnsupportedAlgorithm,
    cryptography.exceptions.AlreadyFinalized,
    cryptography.exceptions.AlreadyUpdated,
    cryptography.exceptions.NotYetFinalized,
    cryptography.exceptions.InvalidTag,
    cryptography.exceptions.InvalidSignature,
    cryptography.exceptions.InternalError,
    cryptography.exceptions.InvalidKey,
)

HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"  # blinking \033[5m"


class MFAwesomeError(Exception):
    def __init__(self, message: str = None, errors: list = []) -> None:
        self.message = message if message else f"{self.__class__.__name__!s} Error"
        self.errors = errors
        super().__init__(self.message)


def CheckIpython() -> bool:
    try:
        from IPython import get_ipython  # type: ignore

        shell = get_ipython().__class__.__name__
        if shell != "NoneType":
            return True
    except ImportError as e:
        return False
    return False


def TestCheck() -> bool:
    res = os.environ.get("MFAWESOME_TEST", False)
    return bool(res)


def ScreenSafe() -> None:
    boldredstart = "\x1b[1m\x1b[38;5;196m"
    reset = "\x1b[0;0;39m"
    if TestCheck():
        newline = "\n"
        print(f"{newline}{boldredstart}{'='*80}{newline}Test mode, screen clearning disabled{reset}")
        return
    try:
        if CheckIpython():
            from IPython.display import clear_output

            clear_output(wait=False)
            return
    except Exception as e:
        pass
    ostype = platform.platform().lower()
    if ostype.startswith("windows"):
        os.system("cls")  # noqa: S607, S605
    elif ostype.startswith(("linux", "darwin")):
        os.system("clear")  # noqa: S605, S607
    else:
        print(f"{boldredstart}Unable to clear output for os type {platform.platform()}{reset}")
    sys.stdout.write("\x1b[?25h")
    sys.stdout.flush()


class KILLED(MFAwesomeError):
    def __init__(self, message: str = "Unknown reason", doexit: bool = True) -> None:
        self.message = message
        super().__init__(message)
        self.critstart = "\x1b[0;0;39m\x1b[0;37;41m"
        self.boldredstart = "\x1b[1m\x1b[38;5;196m"
        self.reset = "\x1b[0;0;39m"
        ScreenSafe()
        if CheckIpython():
            print(f"{self.boldredstart}MFAwesome killed (iPython): {self.message}{self.reset}")
            return
        if doexit:
            self.exit()

    def exit(self) -> None:
        print(f"{self.boldredstart}MFAwesome killed (terminal): {self.message}{self.reset}")
        if EXCEPTIONTESTMODE:
            return
        sys.stdout.write("\n")
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()
        sys.exit(1)


def flatten(*lst: list, sep: str = " ") -> str:
    if not lst:
        return ""

    def _flatten(lst: list) -> Generator:
        for item in lst:
            if isinstance(item, list | tuple | set):
                yield from _flatten(item)
            else:
                yield str(item)

    return sep.join(_flatten(lst))


def printerr(s):
    boldredstart = "\x1b[1m\x1b[38;5;196m"
    reset = "\x1b[0;0;39m"
    print(boldredstart + flatten(s) + reset)


def printcrit(s):
    critstart = "\x1b[0;0;39m\x1b[0;37;41m"
    reset = "\x1b[0;0;39m"
    print(critstart + flatten(s) + reset)


class MFANoTracebackError(MFAwesomeError):
    def __init__(self, message: str = None, errors: list = []) -> None:
        self.message = message if message else f"{self.__class__.__name__!s} Error"
        printerr(self.message)
        self.errors = errors
        super().__init__(self.message, self.errors)
        if EXCEPTIONTESTMODE:
            return
        sys.exit(1)


class StopIPython(Exception):
    def _render_traceback_(self):
        pass


class NTPError(MFAwesomeError):
    def __init__(self, message: str = "NTPTime Error") -> None:
        self.message = message
        super().__init__(self.message)


class NTPInvalidServerResponseError(NTPError):
    pass


class NTPTimeoutError(NTPError):
    pass


class NTPRequestError(NTPError):
    pass


class NTPAllServersFailError(NTPError):
    pass


class NoInternetError(NTPError):
    def __init__(self, message: str = "This device does not appear to have a working internet connection") -> None:
        self.message = message
        super().__init__(self.message)


class Invalid2FACodeError(MFAwesomeError):
    def __init__(self, message: str | None = None):
        self.message = message if message else f"{self.__class__.__name__!s} Error"
        super().__init__(self.message)


def getExceptionNameError(e: type) -> str:
    return e.__class__.__name__


class ConfigError(MFANoTracebackError):
    def __init__(self, message: str | None = None):
        self.message = message if message else f"{self.__class__.__name__!s} Error"
        super().__init__(self.message)


class ConfigNotFoundError(ConfigError):
    def __init__(self, message=None):
        self.message = message if message else f"{self.__class__.__name__!s} Error - check 'mfa config debug'"
        super().__init__(self.message)


class MaxPasswordAttemptsError(ConfigError):
    pass


class DependencyMissingError(MFAwesomeError):
    pass


class ExternalDependencyError(MFAwesomeError):
    pass


class CryptographyError(MFAwesomeError):
    pass


class DecryptionError(CryptographyError):
    pass


class IncorrectPasswordOrSaltError(CryptographyError):
    pass


class EncryptionError(CryptographyError):
    pass


class KeyGenerationError(CryptographyError):
    pass


class ScreenResizeError(MFANoTracebackError):
    pass


class CritStopError(MFAwesomeError):
    def __init__(self, msg: str):
        self.message = f"CRITSTOP: {msg}"
        super().__init__(self.message)


class xTestComplete(MFAwesomeError):
    pass


class UnhandledException(MFAwesomeError):
    pass


class xTestFailError(MFAwesomeError):
    pass


class MissingExtrasDependencies(MFAwesomeError):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class QRScanError(MFAwesomeError):
    pass


class QRImportNotSupportedError(MFAwesomeError):
    pass


class ArgumentError(MFANoTracebackError):
    pass


class ArgumentErrorIgnore(MFAwesomeError):
    pass

    # self.message = message
    # super().__init__.message()


# class ArgumentError(MFAwesomeError):
#     def __init__(self, message: str) -> None:
#         printerr(f"MFA Argument Error: {message}")
#         sys.exit(1)
#         # self.message = message
#         # super().__init__.message()
