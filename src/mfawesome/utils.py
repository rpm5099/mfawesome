from __future__ import annotations

import asyncio
import base64
import binascii
import concurrent
import contextlib
import copy
import datetime
import functools
import inspect
import ipaddress
import logging
import os
import pathlib
import platform
import re
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import traceback
import types
import urllib
from collections.abc import Callable, Generator, KeysView
from contextlib import suppress
from dataclasses import dataclass
from difflib import get_close_matches
from pathlib import Path
from typing import TYPE_CHECKING, Any, AnyStr, ClassVar, TypeVar

import numpy as np

# import requests
import rich.text
from rich import print as rprint

xAny = Any
PRINT = print
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"

try:
    import cchardet as chardet
except ImportError:
    with suppress(ImportError):
        import chardet


try:
    import orjson as json
except ImportError:
    import json

from mfawesome.exception import Invalid2FACodeError, ScreenResizeError

if TYPE_CHECKING:
    import ipaddress

logger = logging.getLogger("mfa")


def PathEx(p: str | Path) -> Path:
    if p == ".":
        return Path().cwd()
    if not p:
        return None
    if "$" in str(p):
        p = os.path.expandvars(p)
    if isinstance(p, str):
        p = Path(p)
    if str(p).startswith("~"):
        p = p.expanduser()
    p = p.resolve(strict=False)
    return p


def PathExFile(p: str | Path):
    p = PathEx(p)
    if not p.is_file():
        raise TypeError(f"{p!s} does not exist")
    return p


def sjoin(*a):
    b = set()
    for x in a:
        b = b.union(x)
    return b


def DownloadVCRedist(vc_url: str = "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe", saveas: Path = Path("/tmp/vcredist_x64.exe")):
    """
    Required for pyzbar on Windows.  Option is a dependency of Qreader when
    installing mfawesome[all]
    """
    with urllib.request.urlopen(vc_url) as f:
        data = f.read()
    saveas.write_bytes(data)
    return saveas


RetType = TypeVar("RetType")

def GetOSFlavor():
    if platform.system() == "Linux":
        # check if debian
        if shutil.which("apt"):
            return "debian"
        if shutil.which("yum") or shutil.which("dnf"):
            return "rhel"
        if shutil.which("pkg"):
            return "bsd"
        if shutil.which("apk"):
            return "alpine"
        if shutil.which("zypper"):
            return "suse"
        if shutil.which("pacman"):
            return "arch"
        if shutil.which("emerge"):
            return "gentoo"
        if shutil.which("slackpkg"):
            return "slackware"
        print("unknown Linux flavor")
    elif platform.system().lower() == "Windows":
        print("Windows OS")
    else:
        raise OSError(f"Unknown OS type: {platform.system()}")


def InstallLibZbar():
    doit = check_yes_no(colors("BOLD_ORANGE", "Libzbar is not installed, would you like to try to install it now?"))
    if doit:
        osf = GetOSFlavor()
        if osf == "debian":
            result = subprocess.Popen(["sudo", "apt-get", "install", "libzbar0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif osf == "rhel":
            result = subprocess.Popen(["sudo", "yum", "install", "zbar-libs"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            raise NotImplementedError(f"Installation of libzbar for OS type {osf} is not implemented")
        # check return type - None is coming from Popen
        logger.critical(f"{result.returncode=} {result.stderr.read()=} {result.stdout.read()=} {result.errors=}")
        if result.returncode != 0:
            raise OSError(f"Libzbar installation failed with error: {result.stderr.read()!s}")
    else:
        sys.exit(1)


class TimeoutD:
    """
    Decorator class to force timeout limits on arbitrary functions.
    If a timeout of -1 is provided the timeout will be disabled.
    """

    def __init__(self, timeout: float, exception_type: Exception = TimeoutError):
        self.timeout = timeout + 0.05 if timeout != -1 else timeout
        self.exception_type = exception_type

    def __call__(self, func: Callable) -> Callable:
        self.func = func
        if self.timeout == -1:
            return self.run_normally_wrapper()
        if asyncio.iscoroutinefunction(func):
            return self.coroutine_wrapper()
        return self.threaded_wrapper()

    def run_normally_wrapper(self) -> Callable:
        @functools.wraps(self.func)
        def decorated(*args: tuple, **kwargs: dict) -> Callable:
            return self.func(*args, **kwargs)

        return decorated

    def threaded_wrapper(self) -> Callable:
        @functools.wraps(self.func)
        def decorated(*args: tuple, **kwargs: dict) -> Callable:
            def start_loop(loop: asyncio.events.AbstractEventLoop) -> None:
                asyncio.set_event_loop(loop)
                loop.run_forever()
                # loop.call_soon_threadsafe(loop.close)  # appears unnecessary

            def stop_loop(loop: asyncio.events.AbstractEventLoop) -> None:
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                # loop.call_soon_threadsafe(loop.stop)  # doesnt appear to do anything

            async def async_func(tfunc: Callable, *args: tuple, **kwargs: dict) -> RetType:
                return tfunc(*args, **kwargs)

            afunc = async_func(self.func, *args, **kwargs)
            new_loop = asyncio.new_event_loop()
            new_thread = threading.Thread(target=start_loop, args=(new_loop,), daemon=True)
            new_thread.start()
            future = asyncio.run_coroutine_threadsafe(afunc, new_loop)
            try:
                result = future.result(timeout=self.timeout)
            except concurrent.futures.TimeoutError:
                stop_loop(new_loop)
                raise self.exception_type  # noqa: B904
            else:
                return result

        return decorated

    def coroutine_wrapper(self) -> Callable:
        @functools.wraps(self.func)
        async def decorated(*args: tuple, **kwargs: dict) -> RetType:
            try:
                result = await asyncio.wait_for(self.func(*args, **kwargs), timeout=self.timeout)
            except TimeoutError:
                raise self.exception_type  # noqa: B904
            else:
                return result

        return decorated


def ValidateIP(ipstr: str) -> bool:
    try:
        ipaddress.ip_address(ipstr)
    except ValueError:
        return False
    else:
        return True


def FF(*args):
    return f"{flatten(args)}"


def PrintList(L, desc=None) -> None:
    if desc is not None:
        print(desc)
    tab = "\t"
    L = sorted(list(L))
    for i, x in enumerate(L):
        print(f"{tab}{i}: {x}")


def GetPythonDir() -> Path:
    return (Path(sys.executable) / "../../").resolve()


def PrintStack(ipython_filter: bool = True) -> None:
    stack = traceback.extract_stack()[:-1]
    ipython_filters = ["IPython", "ipykernel", "asyncio", "asyncio.py", "traitlets", "ipykernel_launcher.py", "<frozen runpy>"]
    filters = []
    if ipython_filter:
        filters.append(ipython_filters)
    entries = []
    pythondir = GetPythonDir()
    for i, entry in enumerate(stack):
        stackpos = len(stack) - i - 1
        entrypath = Path(entry.filename)
        if pythondir in entrypath.parents:
            entrypath = entrypath.relative_to(pythondir)
        parts = Path(entry.filename).parts
        if any(any(x in fltr for x in parts) for fltr in filters):
            # print("SKIPPING: ", (stackpos, entry.filename, entry.name, entry.lineno, entry.line))
            continue

        entries.append((stackpos, entry.filename, entry.name, entry.lineno, entry.line))
        print((stackpos, entry.filename, entry.name, entry.lineno, entry.line))


def makestr(
    x: xAny,
    encoding: str = "autodetect",
    errors: str = "backslashreplace",
    forcenoerror: bool = False,
    delim: str = " ",
    detectlimit: int = 200,
) -> str:
    r"""
    Error Types are:
        strict - raise error
        ignore - leave out
        replace - replace with ?
        xmlcharrefreplace - replace with XML character reference
        backslashreplace - inserts \\uNNNN escape sequence - this seems preferred
        namereplace - inserts \\N{...}

    Simple dict's that are json serializable without any special handling will be converted
    to json, but flattening the dictionary first may be a better option.
    """
    binarytypes = (bytes, bytearray, memoryview)
    try:
        if x is None:
            return ""
        if isinstance(x, binarytypes):
            if encoding == "autodetect" and "chardet" in locals():
                enc = chardet.detect(x[0:detectlimit])["encoding"]  # type: ignore
                return x.decode(enc, errors=errors)
            return x.decode(errors=errors)
        if isinstance(x, str):
            return x
        if isinstance(x, int | float):
            return str(x)
        if isinstance(x, list | tuple):
            return delim.join(map(makestr, x))
        if isinstance(x, dict):
            return str(json.dumps(dict))
        raise ValueError(f"Cannot convert value of type {type(x)} to str: {x}")
    except Exception as e:
        if forcenoerror:
            return ""
        raise e


def jsondump(*args: list, **kwargs: dict) -> str:
    if "orjson" in json.__file__:
        if indent := kwargs.pop("indent", None):  # noqa: SIM102
            if indent is True:
                kwargs["option"] = json.OPT_INDENT_2
        return json.dumps(*args, **kwargs).decode()
    if indent := kwargs.get("indent"):
        indent = 0
        if indent is True:
            kwargs["indent"] = 4
    return json.dumps(*args, **kwargs)


def IsIPython():
    try:
        from IPython import get_ipython  # type: ignore
        from IPython.display import clear_output, display

        return not sys.stdin.isatty()
    except ImportError as e:
        return False


if IsIPython():
    from IPython import get_ipython  # type: ignore
    from IPython.display import clear_output, display

    def doDisplay(*args: list, **kwargs: dict) -> None:
        global PRINT
        isinstance(PRINT, types.BuiltinFunctionType)
        displaypartial = functools.partial(display, *args)
        if kwargs.pop("flush") is True:
            sys.stdout.flush()
        PRINT = displaypartial


def systimestr() -> str:
    return colors("green", f"System Time: {gettime()}")


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


def logprint(*s: list, sep: str = " ", levelsback: int = 1) -> None:
    frame = inspect.stack()[levelsback]
    filename = Path(frame[1]).name
    funcname = frame[3]
    funcline = frame[2]
    timestamp = getdatetime()
    msg = f"{timestamp}-{filename}-{funcname}-L{funcline}: {flatten(s, sep=sep)}"
    print(msg)


@dataclass
class ANSIColors:
    # COLOR PICKER
    # https://g.co/kgs/LKxPvmR
    BLACK = "\x1b[30m"
    BLUE = "\x1b[34m"
    CYAN = "\x1b[36m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33;20m"
    DEBUG_BLUE = "\x1b[38;2;40;177;249m"
    BOLD_ORANGE = "\x1b[38;5;220m\x1b[1m"
    ORANGE = "\x1b[38;5;220m"
    LIGHTBLACK_EX = "\x1b[90m"
    LIGHTBLUE_EX = "\x1b[94m"
    LIGHTCYAN_EX = "\x1b[96m"
    LIGHTGREEN_EX = "\x1b[92m"
    LIGHTMAGENTA_EX = "\x1b[95m"
    LIGHTRED_EX = "\x1b[91m"
    LIGHTWHITE_EX = "\x1b[97m"
    LIGHTYELLOW_EX = "\x1b[93m"
    MAGENTA = "\x1b[35m"
    PURPLE = "\x1b[1;35;40m"
    RED = "\x1b[31m"
    BOLD_BOLD_RED = "\x1b[1m\x1b[1m\x1b[38;5;196m"
    MAX_RED = "\x1b[1m\x1b[38;5;196m"
    # RESET = "\x1b[39m"
    RESET = "\x1b[0;0;39m"
    ROYAL_BLUE = "\x1b[38;5;21m"
    WHITE = "\x1b[37m"
    DARK_BLUE = "\x1b[38;5;20m"  # type: ignore
    GREY = "\x1b[38;20m"  # type: ignore
    BOLD_BLACK = "\x1b[1m\x1b[30m"
    BOLD_BLUE = "\x1b[1m\x1b[34m"
    BOLD_BOLD = "\x1b[1m\x1b[1m"
    BOLD_CYAN = "\x1b[1m\x1b[36m"
    BOLD_DARK_BLUE = "\x1b[1m\x1b[38;5;20m"
    BOLD_DEBUG_BLUE = "\x1b[1m\x1b[38;2;40;177;249m"
    BOLD_FORCE_NO_COLOR = "\x1b[1m\x1b[0m"
    BOLD_GREEN = "\x1b[1m\x1b[32m"
    BOLD_GREY = "\x1b[1m\x1b[38;20m"
    BOLD_LIGHTBLACK_EX = "\x1b[1m\x1b[90m"
    BOLD_LIGHTBLUE_EX = "\x1b[1m\x1b[94m"
    BOLD_LIGHTCYAN_EX = "\x1b[1m\x1b[96m"
    BOLD_LIGHTGREEN_EX = "\x1b[1m\x1b[92m"
    BOLD_LIGHTMAGENTA_EX = "\x1b[1m\x1b[95m"
    BOLD_LIGHTRED_EX = "\x1b[1m\x1b[91m"
    BOLD_LIGHTWHITE_EX = "\x1b[1m\x1b[97m"
    BOLD_LIGHTYELLOW_EX = "\x1b[1m\x1b[93m"
    BOLD_MAGENTA = "\x1b[1m\x1b[35m"
    BOLD_NONE = "\x1b[1m"
    BOLD_RED = "\x1b[38;5;196m\x1b[1m"  # "\x1b[1m\x1b[31m"
    BOLD_UNDERLINE_RED = "\x1b[1;4m\x1b[38;5;196m"  # "\x1b[1m\x1b[31m"
    BOLD_ROYAL_BLUE = "\x1b[1m\x1b[38;5;21m"
    BOLD_WHITE = "\x1b[1m\x1b[37m"
    BOLD_YELLOW = "\x1b[1m\x1b[33;20m"
    WHITE_ON_RED = "\x1b[0;37;41m"
    FORCE_NO_COLOR = "\x1b[0m"
    BLACK_ON_GREEN = "\x1b[48;5;40m\x1b[38;5;233m\x1b[1m"  # "\x1b[48;5;46m\x1b[38;5;0m\x1b[1m"  # "\x1b[1;30;42m"
    BLACK_ON_RED = "\x1b[48;5;196m\x1b[38;5;233m\x1b[1m"  # "\x1b[48;5;197m\x1b[38;5;0m\x1b[1m"
    WHITE_ON_GREEN = "\x1b[1;37;42m"
    BLUE_ON_BLACK = "\x1b[48;5;69m\x1b[38;5;233m\x1b[1m"
    BOLD = "\x1b[1m"
    BOLD_UNDERLINE = "\033[1;4m"
    NONE = ""

    @staticmethod
    def demo(teststr: str = "ansicolors DEMO OF COLORS") -> None:
        for x in dir(ANSIColors):
            if x.startswith("_"):
                continue
            if x.startswith("demo"):
                continue
            tests = f"{getattr(ANSIColors, x)}{x}    {teststr}{ANSIColors.RESET}"
            print(f"{tests} - {tests!r}")

    @staticmethod
    def ColorTest() -> None:
        esc = "\x1b["
        reset = f"{esc}39m"
        for x in range(9):
            for y in range(30, 38):
                s = []
                for z in range(40, 48):
                    color = f"{esc}{x};{y};{z}m"
                    s.append(f"{color} {color!r} {reset}")
                print(" ".join(s))


def stripcolors(s: str) -> str:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", s)


def colors(*s: list[str]) -> str:
    """Return colored string.  Uses raw ANSI codes rather than a library.  The color is the first argument colors("red", "some string", "another string")"""
    if len(s) == 1:
        return " ".join(s)
    color = s[0]
    return f"{ANSIColors.RESET}{getattr(ANSIColors, color.upper())}{flatten(s[1:])}{ANSIColors.RESET}"


def colorstring(s: str, color: str | None = None) -> rich.text.Text:
    return rich.text.Text.assemble((s, color))


def levelprint(level: str, *s: list[str], retstr: bool = False) -> str | None:
    if level.lower() == "dbg":
        color = "bold_debug_blue"
    elif level.lower() == "norm":
        color = "bold"
    elif level.lower() == "ok":
        color = "bold_green"
    elif level.lower() == "warn":
        color = "ORANGE"
    elif level.lower() == "err":
        color = "max_red"
    elif level.lower() == "crit":
        color = "white_on_red"
    else:
        raise ValueError(f"Invalid color level: {level}")
    s = flatten(*s)
    if retstr:
        return colors(color, s)
    if logger.getEffectiveLevel() == 10:
        logprint(colors(color, s), levelsback=3)
        return None
    print(colors(color, s))
    return None


def printdbg(*s: list[str], retstr: bool = False) -> None:
    return levelprint("dbg", *s, retstr=retstr)


def printnorm(*s: str, retstr: bool = False) -> None:
    return levelprint("norm", *s, retstr=retstr)


def printok(*s: list[str], retstr: bool = False) -> None:
    return levelprint("ok", *s, retstr=retstr)


def printwarn(*s: list[str], retstr: bool = False) -> None:
    return levelprint("warn", *s, retstr=retstr)


def printerr(*s: list[str], retstr: bool = False) -> None:
    return levelprint("err", *s, retstr=retstr)


def printcrit(*s: list[str], retstr: bool = False) -> None:
    return levelprint("crit", *s, retstr=retstr)


def resolvepath(fname: str | Path) -> str:
    return str(Path(fname).resolve())


def toby(p: xAny) -> bytes:
    if isinstance(p, str):
        return p.encode(errors="backslashreplace")
    return p


def bytify(func: Callable) -> Callable:
    """
    Decorator to take all string function arguments and convert them to bytes
    """

    @functools.wraps(func)
    def bytifywrapper(*args: list, **kwargs: dict) -> xAny:
        args = [toby(x) for x in args]
        kwargs = {k: toby(v) if "str" not in k else v for k, v in kwargs.items()}
        return func(*args, **kwargs)

    return bytifywrapper


def bytifykw(*modifyargs: list) -> xAny:
    def _bytify(func: Callable) -> Callable:
        """
        Decorator to take specified keyword function arguments and convert them to bytes.
        If you specify a non-existent argument there is no warning as that is common when
        a keyword argument is simply not required
        """

        @functools.wraps(func)
        def bytifywrapper(*args: list, **kwargs: dict) -> xAny:
            kwargs = {k: toby(v) if k in modifyargs and isinstance(v, str) else v for k, v in kwargs.items()}
            return func(*args, **kwargs)

        return bytifywrapper

    return _bytify


def IncrementToDeconflict(conflict: str, existing: list[str]) -> str:
    if conflict not in existing:
        return conflict
    i = 1
    originalconflict = copy.copy(conflict)
    while conflict in existing:
        conflict = f"{originalconflict} ({i})"
        i += 1
        if i > 100:
            raise RuntimeError(f"Could not find non-conflicting name for {conflict}")
    return conflict


def check_yes_no(msg: str = "Yes or No?") -> bool:
    if IsIPython():
        msg = stripcolors(msg)
    msg += " (y/n)?"
    inp = input(msg)
    return inp.lower() in ["y", "yes", "yeah"]


def FuzzyStrMatches(val: str, targets: list[str], n: int = 10, cutoff: float = 0.9) -> list[str]:
    if not isinstance(targets, list | set | KeysView):
        raise TypeError(f"Targets must be a list or string, not {type(targets)}")
    if val is None:
        return targets
    closeenough = []
    for i, target in enumerate(targets):
        if val.lower() in target.lower():
            closeenough.append(target)
    trctargets = [x[0 : len(val)] for x in targets]
    trcmatches = get_close_matches(val, trctargets, n=n, cutoff=cutoff)
    for x in trcmatches:
        for y in targets:
            if y.startswith(x):
                closeenough.append(y)
    nocasetargets = [x.lower() for x in targets]
    nocasematches = get_close_matches(val, nocasetargets, n=n, cutoff=cutoff)
    for x in nocasematches:
        for y in targets:
            if x.lower() == y.lower():
                closeenough.append(y)
    return list(set(closeenough))


def FindStrMatch(val: str, targets: list[str]) -> list[str] | str | None:
    if not isinstance(targets, list | set | KeysView):
        raise TypeError(f"Targets must be a list or string, not {type(targets)}")

    def closematches(val: str, targets: list) -> str | None:
        tm = get_close_matches(val, [x[0 : len(val)] for x in targets])
        if len(tm) > 0:
            for target in targets:
                if target.startswith(tm[0]):
                    return target
        possible = [x for x in tm if x.startswith(val)]
        if len(possible) == 0:
            return None
        return possible

    possible = []
    for t in targets:
        if val in t or t.startswith(val):
            possible.append(t)
    if len(possible) == 1:
        return possible[0]
    if len(possible) == 0:
        return closematches(val, targets)
    return None


def get_term_size(defaultwidth: int = 150, defaultheight: int = 50) -> tuple[int, int]:
    try:
        width, height = os.get_terminal_size()
    except OSError as e:
        # probably in jupyter
        return defaultwidth, defaultheight
    else:
        return width, height


def print_sep_line(width: int | None = None, color: str = "BOLD_LIGHTBLACK_EX") -> None:
    width = width if width else get_term_size()[0]
    line = colors(color, "\u2500" * width)
    print(line)


def print_with_sep_line(printfunc: Callable, msg: xAny, color: str = "BOLD_LIGHTBLACK_EX", above: bool = False) -> None:
    msglen = None
    with contextlib.suppress(Exception):
        msglen = len(msg)
    if above is True:
        print_sep_line(width=msglen, color=color)
    printfunc(msg)
    if above is False:
        print_sep_line(width=msglen, color=color)


def clear_output_ex() -> None:
    isipython = False
    try:
        if IsIPython() is not False:
            from IPython.display import clear_output

            isipython = True
            clear_output(wait=False)
            sys.stdout.flush()
            return
    except (ImportError, NameError) as e:
        pass
    except Exception as e:
        raise RuntimeError(f"Unknown error attempting to clear display output") from e
    if isipython is False:
        if platform.system() == "Windows":
            os.system("cls")
        elif platform.system() == "Linux":
            os.system("clear")


def clear_output_line() -> None:
    sys.stdout.write("\r" + get_term_size()[0] * " ")
    sys.stdout.write("\r")
    sys.stdout.flush()


def clear_previous_line() -> None:
    # sys.stdout.write("\033[1A" + get_term_size()[0] * " " + "\033[K")
    print(("\033[F" * 2) + "\n" + get_term_size()[0] * " ", end="\r", flush=True)
    sys.stdout.flush()


def clear_output_lines(n: int) -> None:
    LINE_UP = "\x1b[1A"
    LINE_CLEAR = "\x1b[2K"
    for i in range(n):
        print(LINE_UP, end=LINE_CLEAR)
    sys.stdout.flush()


@bytify
def shannon_entropy_native(data: bytes, mode: str | bytes = b"binary", customalpha: str | None = None) -> float:
    """
    NOTE:  This is a native python implementation of entropy and is MUCH slower than optimized libraries

    Maximum entropy is scaled to 100, anything with an entropy above ~94 is highly likely to be encrypted or compressed.

    Most shannon entropy implementations use a log with base 2, however using a log base that
    matches the number of possible characters allows for a scaled result from 0-100.

    Baseline comparison:
    Normal Compiled Binary: ~60-80
    Compressed/Encrypted Data: >94 (usually around 99+)
    """
    logger.debug(f"{type(data)=} {data=}")
    data = np.frombuffer(data, dtype="B")
    if customalpha and mode != b"custom":
        logger.debug("customalpha being ignored, not in custom mode!")
    if mode == b"custom" and not isinstance(customalpha, bytes):
        raise ValueError(f"In mode custom the parameter customalpha with type bytes is required - received {type(customalpha)}")
    if len(data) == 0:
        return 0.0
    if mode == b"binary":
        unique, counts = np.unique(data, return_counts=True)
        p = counts / counts.sum(axis=0, keepdims=True)
        entropy = (-p * (np.log2(p) / np.log2(256))).sum(axis=0)
        return entropy * 100
    if mode == b"printable":
        alpha = set(bytes(string.printable, "ascii"))
    elif mode == b"hex":
        alpha = set(b"abcdef0123456789")
    elif mode == b"custom":
        alpha = set(customalpha)
    else:
        raise ValueError(f"Unknown mode: {mode} - allowable types are binary (default), printable, hex and custom")

    if not set(data).issubset(alpha):
        if mode == b"hex":
            raise ValueError("Non-alphabet bytes found in data. Ensure your hex is lowercase.")
        raise ValueError("Non-alphabet bytes found in data.")
    base = len(alpha)
    unique, counts = np.unique(data, return_counts=True)
    p = counts / counts.sum(axis=0, keepdims=True)
    entropy = (-p * (np.log2(p) / np.log2(base))).sum(axis=0)
    return entropy * 100


def PercentDecode(s: str, limit: int = 5) -> str:
    i = 0
    while "%" in s:
        s = urllib.parse.unquote(s)
        i += 1
    if "%" in s:
        raise RuntimeError(f"Failed to decode percent encoded string: {s}")
    return s


def IsBase32(s: str) -> bool:
    logger.debug(f"{s=} {type(s)=}")
    try:
        base64.b32decode(fix_b32decode_pad(s))
    except binascii.Error as e:
        logger.debug(f"Invalid base32 found: {s} {e!r}")
        return False
    except Exception as e:
        logger.error(f"Invalid base32 secret: {s}")
        return False
    else:
        return True


def fix_b32decode_pad(v: str | None, noerror: bool = True) -> str:
    """Base32 padding must always be 0, 1, 3, 4, or 6"""
    if v is None and noerror:
        return None
    v = v.replace(" ", "").replace("\t", "").upper()
    for pl in [0, 1, 3, 4, 6]:
        try:
            val = v + "=" * pl
            base64.b32decode(v + "=" * pl)
        except binascii.Error as e:
            if str(e) == "Incorect padding":
                continue
        else:
            return val
    return v


def b32decode(v: str) -> str:
    """Base32 padding must always be 0, 1, 3, 4, or 6"""
    if v is None:
        return None
    v = v.replace(" ", "").replace("\t", "").upper()
    err = None
    for pl in [0, 1, 3, 4, 6]:
        try:
            return base64.b32decode(v + "=" * pl)
        except binascii.Error as e:
            err = e
            if str(e) == "Incorect padding":
                continue
    raise Invalid2FACodeError(repr(err)) from err


def ValidateB32(v: str) -> bool:
    if not v:
        return False
    try:
        b32decode(fix_b32decode_pad(v))
        return True
    except Invalid2FACodeError:
        return False


def FastInternetCheck(timeout: float = 0.5) -> bool:
    printdbg("running fast internet check")
    testips = ["151.101.130.219", "104.16.60.8", "50.116.25.154"]
    for ip in testips:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket.SOCK_DGRAM)
            client.settimeout(timeout)
            client.connect((ip, 443))
            client.close()
            printdbg(f"Successfully connected to {ip}:443")
        except TimeoutError as e:
            continue
        else:
            return True
        finally:
            client.close()
    return False


# def CheckInternet(
#     domain: AnyStr = "google.com",
#     url: AnyStr = "https://www.google.com",
#     fallbackping: AnyStr = "8.8.8.8",
#     raise_exceptions: bool = False,
# ) -> bool:
#     logger.critical("Skip this shit - FIXME")
#     return False

#     def pingcheck(ipaddr: str) -> bool:  # | ipaddress.IPAddress) -> bool:
#         return icmplib.ping(ipaddr, count=1, interval=1, timeout=0.5, privileged=False).is_alive

#     logger.critical("SET TIMEOUT HERE!")
#     # def dnscheck(domain: str) -> bool:
#     #    logger.critical("SET TIMEOUT HERE!")
#     #    return dns.resolver.resolve(domain, "A") is not None

#     def URLCheck(url: str) -> bool:
#         return requests.get(url, timeout=3).status_code == 200

#     # try:
#     #     return URLCheck(url=url)
#     # except requests.exceptions.RequestException as urlexception:
#     #     try:
#     #         return dnscheck(domain=domain)
#     #     except dns.exception.DNSException as dnserror:
#     #         try:
#     #             return pingcheck(ipaddr=fallbackping)
#     #         except icmplib.ICMPLibError as icmperror:
#     #             if raise_exceptions:
#     #                 raise ExceptionGroup(
#     #                     "No internet connectivity - HTTP, DNS and ping requests failed!",
#     #                     [urlexception, dnserror, icmplib.ICMPLibError(f"Failed to ping fallback ping {fallbackping}"), icmperror],
#     #                 ) from urlexception
#     #         return False


def CheckFile(fn: str | pathlib.Path) -> bool:
    """Return whether a file is found and is readable"""
    if not fn:
        return False
    f = Path(fn)
    if f.exists and f.is_file() and f.stat().st_size > 0:  # noqa: SIM102
        if os.access(fn, os.R_OK):
            return True
    return False


def hms(n: float) -> str:
    ts = str(datetime.timedelta(seconds=int(n))) + "s"
    if n < 11.0 and n >= 6.0:
        return colors("orange", ts)
    if n < 6.0:
        return colors("bold_red", ts)
    return colors("green", ts)


datef = "%Y-%m-%d"
timetz = "%I:%M:%S%p"
timemil = "%I:%M:%S"
tzf = " %Z"


def fliptimetype(t: time.struct_time | datetime.datetime, tz=None) -> time.struct_time | datetime.datetime:
    if isinstance(t, time.struct_time):
        return datetime.datetime.fromtimestamp(time.mktime(t), tz=tz)
    if isinstance(t, datetime.datetime):
        return t.timetuple()
    raise TypeError(f"Must be of type time.struct_time or datetime.datetime: {type(t)}")


def filenametimestamp() -> str:
    return time.strftime("%Y%m%d_%H%M", time.localtime())


def getdatetime(mil: bool = False, tz: bool = True, zulu: bool = False) -> str:
    fstr = datef + " "
    fstr += timemil if mil else timetz
    fstr += " %Z" if tz else ""
    tobj = time.gmtime() if zulu else time.localtime()
    return time.strftime(fstr, tobj)


def gettime(ts: float | None = None, mil: bool = False, tz: bool = True, zulu: bool = False) -> str:
    fstr = timemil if mil else timetz
    fstr += " %Z" if tz else ""
    tobj = time.localtime(ts) if ts else time.gmtime() if zulu else time.localtime()
    return time.strftime(fstr, tobj)


def printtypeval(obj: xAny) -> None:
    objname = ""
    for name, val in locals().items():
        if val is obj:
            objname = val
    objstr = ""
    with contextlib.suppress(Exception):
        objstr = str(obj)[0:100]
    printdbg(f"{objname} Info - type:{type(obj)} val: {objstr}")


class RunOnlyOnce:
    """
    USE THIS TO MAKE PRINT MESSGES ONLY SHOW ONE TIME
    Decorator to ensure all decorated functions run only ONCE.

    To reset:
        RunOnlyOnce.reset()

    To use:
        @RunOnlyOnce
        def foo(x):
            return x
        print(foo(1))
        print(foo(2))
    """

    RetVal = TypeVar("RetVal")
    funcset: ClassVar[set] = set()

    def __init__(self, customfuncid: str | None = None) -> None:
        self.customfuncid = customfuncid

    def __call__(self, func: Callable):
        @functools.wraps(func)
        def wrapper(*args: tuple, **kwargs: dict) -> RunOnlyOnce.RetVal:
            funcid = self.customfuncid if self.customfuncid else id(func)
            if funcid in RunOnlyOnce.funcset:
                return None
            RunOnlyOnce.funcset.add(funcid)
            return func(*args, **kwargs)

        return wrapper

    @classmethod
    def reset(cls: type[RunOnlyOnce]) -> None:
        cls.funcset = set()


class RunLimit:
    """
    Decorator to ensure all decorated functions run only ONCE.
    Use a custom function id to place limits on groups of functions,
    or functions that may get dynamically redevined (i.e. class member
    functions). The run limit is cumulative and will be set to the highest run
    limit of common function id's.

    To reset:
        RunLimit.reset()

    To use:
        @RunLimit(1)
        def foo(x):
            return x
        print(foo(1))
        print(foo(2))  <- no output
    """

    RetVal = TypeVar("RetVal")
    funcdict: ClassVar[dict] = {}

    def __init__(self, runlimit: int = 1, customfuncid: str | None = None) -> None:
        self.runlimit = runlimit
        self.customfuncid = customfuncid

    def __call__(self, func: Callable):
        @functools.wraps(func)
        def wrapper(*args: tuple, **kwargs: dict) -> RunLimit.RetVal:
            funcid = self.customfuncid if self.customfuncid else id(func)
            if funcid in RunLimit.funcdict:
                RunLimit.funcdict[funcid]["count"] += 1
                RunLimit.funcdict[funcid]["limit"] = max(self.runlimit, RunLimit.funcdict[funcid]["limit"])
            else:
                RunLimit.funcdict[funcid] = {}
                RunLimit.funcdict[funcid]["_func"] = func
                RunLimit.funcdict[funcid]["count"] = 1
                RunLimit.funcdict[funcid]["limit"] = self.runlimit

            if RunLimit.funcdict[funcid]["count"] > RunLimit.funcdict[funcid]["limit"]:
                # print(f"RunLimit of {RunLimit.funcdict[funcid]['limit']} for {funcid} ({RunLimit.funcdict[funcid]['_func'].__name__}) reached!")
                return None
            return func(*args, **kwargs)

        return wrapper

    @classmethod
    def reset(cls: type[RunLimit]) -> None:
        cls.funcdict = {}


def ErrorExitCleanup() -> None:
    clear_output_ex()
    sys.stdout.write(SHOW_CURSOR)
    sys.stdout.flush()
