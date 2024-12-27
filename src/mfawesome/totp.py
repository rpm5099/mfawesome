from __future__ import annotations

import hashlib
import hmac
import logging
import struct
import sys
import time
from collections import namedtuple
from dataclasses import Field, dataclass, fields
from pprint import pformat
from typing import TYPE_CHECKING, Any

import rich
import rich.console
import rich.panel
import rich.progress
import rich.text
from rich import print as rprint
from rich.text import Text

from mfawesome.config import ConfigIO, FilterSecrets, LoadNTPServers, SearchSecrets
from mfawesome.countdownbars import Countdown, CountdownBar, CountdownBars, DoubleCountdown, ProgBar
from mfawesome.exception import (
    KILLED,
    ConfigError,
    Invalid2FACodeError,
    MFAwesomeError,
    NoInternetError,
    NTPError,
    NTPInvalidServerResponseError,
    getExceptionNameError,
)
from mfawesome.ntptime import CorrectedTime
from mfawesome.utils import (
    HIDE_CURSOR,
    PRINT,
    SHOW_CURSOR,
    FindStrMatch,
    FuzzyStrMatches,
    IsIPython,
    b32decode,
    clear_output_ex,
    clear_output_line,
    colors,
    colorstring,
    fix_b32decode_pad,
    get_term_size,
    gettime,
    printcrit,
    printdbg,
    printerr,
    printok,
    printwarn,
)

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("mfa")

NTPCT = None


def init(timeservers):
    global NTPCT
    NTPCT = CorrectedTime(timeservers)


def totpcalc(secret: str, period_offset: int = 0) -> tuple[str, float]:
    """2fa"""
    secret = secret.replace("\t", "")
    # tm = int(time.time() / 30)
    # ts = ntpo.ts + time_offset
    # tm = ts / 30.0
    # time_remaining = (30.0 + time_offset) - (ts % 30.0)
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


def multitotpcalc(secret: str, codecount: int = 2) -> tuple[str, float]:
    """2fa"""
    TOTPCode = namedtuple(
        "TOTPCode",
        ["code", "remaining", "untilvalid", "validtimestamp"],
    )
    codes = []
    for i in range(codecount):
        code, remaining = totpcalc(secret, period_offset=i)
        uv = remaining - 30.0
        TCode = TOTPCode(code, remaining, uv, gettime(NTPCT.time))
        codes.append(TCode)
    return codes


def hotpcalc(secret: str, count: int) -> str:
    """2fa"""
    count = int(count)
    count += 1
    if count < 0:
        raise ValueError(f"HOTP count argument must be a positive integer")
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


def dictgetstr(key: Any, adict: dict, errval: None = None) -> Any:
    """Replacement for repeatedly having somedict.get(someval, None)"""
    val = adict.get(key, errval)
    return val if val is not None else ""


def runhotp(
    configfile: str | Path | None = None,
    filterterm: str | None = None,
    exact: bool = False,
    showsecrets: bool = False,
) -> None:
    """Display matching HOTP results table"""
    with ConfigIO(configfile=configfile) as configio:
        secrets = configio.config["secrets"]
        names = sorted(secrets.keys(), key=str.casefold)
        names = [x for x in names if "hotp" in secrets[x]]
        names = [x for x in names if "counter" in secrets[x]]
        if filterterm is not None:
            names = [x for x in names if filterterm in x] if exact else FuzzyStrMatches(filterterm, names)
        if len(names) == 0:
            raise ConfigError(
                f"No matching HOTP codes found.  (filter term: {filterterm}).  Ensure that all HOTP entries in the config have both an 'hotp' and a 'counter' value.",
            )
        HOTPResult = namedtuple("HOTPResult", ["name", "code", "counter", "user", "secret", "password", "url"])
        results = []
        for name in names:
            secretdata = secrets[name]
            hotpsecret = dictgetstr("hotp", secretdata)
            hotpcounter = dictgetstr("counter", secretdata)
            hotpcode, hotpcounter = hotpcalc(hotpsecret, hotpcounter)
            configio._config["secrets"][name]["counter"] = hotpcounter
            # secretdata["counter"] = hotpcounter
            result = HOTPResult(
                name,
                hotpcode,
                str(hotpcounter),
                dictgetstr("user", secretdata),
                hotpsecret,
                dictgetstr("password", secretdata),
                dictgetstr("url", secretdata),
            )
            results.append(result)
    if len(results) == 0:
        raise RuntimeError("There are no HOTP results, something is wrong")
    console = rich.console.Console()
    tfatable = rich.table.Table(title=rich.text.Text("MFAwesome 2FA HOTP Results", style=rich.style.Style(bgcolor="white", color="black")), show_lines=True)
    tfatable.add_column("Name", justify="left", min_width=20, max_width=50)
    tfatable.add_column("Code", justify="center", style="green", min_width=6)
    tfatable.add_column("Counter", justify="center", style="green", min_width=6)

    fields = ["Name", "Counter", "Code", "User"]
    if showsecrets:
        termwidth = get_term_size()[0]
        if termwidth < 120:
            printwarn(f"Terminal size is only {termwidth} - output may be truncated")
        fields += ["User", "HOTP", "Password", "URL"]
        tfatable.add_column("User", justify="center")
        tfatable.add_column("HOTP", justify="center", style="yellow")
        tfatable.add_column("Password", justify="center", style="yellow")
        tfatable.add_column("URL", justify="center", style="blue")
    for result in results:
        if showsecrets:
            tfatable.add_row(*list(result))
        else:
            tfatable.add_row(*list(result)[:-4])
    print("\n")
    console.print(tfatable)


def RemainingTime(period_offset: int = 0) -> float:
    return float(30.0 - (NTPCT.time % 30)) + (30.0 * period_offset)


@dataclass
class TFAResult:
    name: str
    totp: str | None = None
    code: int | str | None = None
    nextcode: int | str | None = None
    user: str | None = None
    password: str | None = None
    url: str | None = None
    # remaining: float | None = None
    valid: bool | None = None
    error: str | None = None
    showsecrets: bool | None = False
    showerr: bool | None = True
    _temp: bool = False

    def __post_init__(self) -> None:
        """
        _summary_
        """
        if self._temp is False:
            if isinstance(self.code, int):
                self.code = str(self.code)
            if isinstance(self.nextcode, int):
                self.nextcode = str(self.nextcode)
            self.fmt = self.ApplyValidityFormatting()

    def ApplyValidityFormatting(self) -> TFAResult:
        """
        _summary_

        :return: _description_
        :rtype: TFAResult
        """
        tmp = TFAResult(
            name=self.name,
            totp=self.totp.strip("="),
            code=self.code,
            nextcode=self.nextcode,
            user=self.user,
            password=self.password,
            url=self.url,
            valid=self.valid,
            error=self.error,
            showsecrets=self.showsecrets,
            showerr=self.showerr,
            _temp=True,
        )
        cls_fields: tuple[Field, ...] = [x.name for x in fields(tmp.__class__)]
        if not self.showsecrets:
            tmp.totp = ""
            tmp.password = ""
        if self.valid is False:
            for fld in cls_fields:
                if isinstance(getattr(tmp, fld), bool | TFAResult):
                    continue
                if fld in ("code", "nextcode"):
                    newval = "ERROR!"
                elif fld == "totp":
                    errmsg = ""
                    if tmp.showerr:
                        errmsg = " - " + repr(tmp.error)
                    newval = getattr(tmp, fld) + errmsg
                elif fld == "error":
                    if getattr(tmp, fld) is None:
                        newval = ""
                else:
                    newval = getattr(tmp, fld)
                if newval is None:
                    newval = ""
                setattr(tmp, fld, colorstring(newval, "bold red"))
        else:
            if tmp.error is None:
                tmp.error = ""
            elif not isinstance(tmp.error, str):
                tmp.error = str(tmp.error)
            tmp.error = colorstring(tmp.error, "bold red")
        return tmp

    def display(self) -> None:
        """
        _summary_
        """
        tmp2 = self.ApplyValidityFormatting()
        cls_fields: tuple[Field, ...] = [x.name for x in fields(tmp2.__class__)]
        for fld in cls_fields:
            if isinstance(getattr(tmp2, fld), bool):
                continue
            attr = getattr(tmp2, fld)
            if not isinstance(attr, rich.text.Text):
                attr = Text(str(attr))
            rprint(Text(fld + ": ") + attr)

    def get_fields_as_tuple(self, fields: list) -> tuple[str]:
        return tuple([getattr(self.fmt, fld) for fld in fields])


class TFAResults:
    def __init__(
        self,
        showsecrets: bool = False,
        showerr: bool = False,
        endtimer: bool = True,
        clearscreen: bool = True,
        mintime: float = 12.0,
        now: bool = False,
        timeservers: list | None = None,
    ) -> None:
        self.showsecrets = showsecrets
        self.showerr = showerr
        self.endtimer = endtimer
        self.clearscreen = clearscreen
        self.mintime = mintime
        self.now = now
        self.timeservers = timeservers
        # self.ntpo = ntptime.NTPTime(updatenow=False)
        self.ntpo = NTPCT
        self.remaining = 0.0
        self.console = rich.console.Console()
        self.tfatable = rich.table.Table(
            # title=rich.text.Text("MFAwesome 2FA Results", style=rich.style.Style(reverse=True)),
            title=rich.text.Text(
                "MFAwesome 2FA TOTP Results",
                style=rich.style.Style(bgcolor="white", color="black"),
            ),
            show_lines=True,
        )
        self.tfatable.add_column("Name", justify="left", min_width=20, max_width=50)
        self.tfatable.add_column("Code", justify="center", style="green", min_width=6)
        self.tfatable.add_column(
            "NextCode",
            justify="center",
            style="grey53",
            min_width=6,
        )
        self.tfatable.add_column("User", justify="center")
        self.fields = ["Name", "Code", "NextCode", "User"]
        if self.showsecrets:
            termwidth = get_term_size()[0]
            if termwidth < 120:
                printwarn(
                    f"Terminal size is only {termwidth} - output may be truncated",
                )
            self.fields += ["TOTP", "Password", "URL"]
            self.tfatable.add_column("TOTP", justify="center", style="yellow")
            self.tfatable.add_column("Password", justify="center", style="yellow")
            self.tfatable.add_column("URL", justify="center", style="blue")
        self.results = {}
        # self.remaining = 30
        self.ipython = IsIPython()

    def __setitem__(self, tfaresult: TFAResult, _) -> None:
        """
        _summary_

        :param tfaresult: _description_
        :type tfaresult: TFAResult
        :param _: _description_
        :type _: _type_
        """
        tfaresult.showerr = self.showerr
        tfaresult.showsecrets = self.showsecrets
        self.results[tfaresult.name] = tfaresult
        # self.remaining = tfaresult.remaining

    def __getitem__(self, name: str) -> object:
        """
        _summary_

        :param name: _description_
        :type name: str
        :raises KeyError: _description_
        :return: _description_
        :rtype: object
        """
        if match := FindStrMatch(name, self.results.keys()):
            return self.results[match]
        raise KeyError(f"No matching result with name similar to {name}")

    def ShowCodes(self) -> float:
        """
        _summary_

        :raises KILLED: _description_
        :return: _description_
        :rtype: _type_
        """
        repeat = False
        fields = [x.lower() for x in self.fields]
        for result in self.results.values():
            self.tfatable.add_row(*result.get_fields_as_tuple(fields))
        try:
            # logger.debug(f"{RemainingTime(self.ntpo)=} {self.remaining=}")
            self.remaining = RemainingTime()
            # logger.debug(f"{self.remaining=} {self.mintime=} {self.now=}")
            if self.remaining < self.mintime:
                if self.now is False:
                    Countdown(f"Waiting for new codes:", self.remaining + 1)
                else:
                    repeat = True
            print("\n")
            self.console.print(self.tfatable)
            if self.endtimer:
                # Clock timers disabled in favor of using bars, unless the bars cause problems
                # Countdown("Codes expiring in: ", self.remaining)
                # CountdownBar(msg="Codes expiring in: ", timertime=self.remaining).begin()

                progbar = ProgBar(msg="Codes expiring in", timertime=self.remaining, fixedbartime=30)
                if self.ipython:  # noqa: SIM108
                    cbars = CountdownBars(progbar, freq=0.2, systime=True, textabove=self.tfatable)
                else:
                    cbars = CountdownBars(progbar, freq=0.2, systime=True)
                cbars.begin()
                if self.clearscreen:
                    clear_output_ex()
                printok("MFAwesome: Codes expired!")
            else:
                PRINT(f"Codes expiring in: {colors('green', int(self.remaining))}", end="\r")
            if repeat and self.endtimer:
                repeat = False
                self.ShowCodes()
        except KeyboardInterrupt as e:
            raise KILLED(f"Got keyboard interrupt with {self.remaining:0.1f}s remaining!") from e
        finally:
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()
        return self.remaining


def multitotp(
    secrets: dict,
    # ntpo: ntptime.NTPTime | None = None,
    now: bool = False,
    showsecrets: bool = False,
    endtimer: bool = True,
    showerr: bool = False,
    filterterm: str | None = None,
    clearscreen: bool = True,
    exact: bool = False,
    mintime: float = 12.0,
    timeservers: list | None = None,
) -> None:
    """
    _summary_

    :param secrets: Dictionary of secrets, usually from the config
    :type secrets: dict
    :param now: Do not wait for new codes with 30s remaining on them, defaults to False
    :type now: bool, optional
    :param showsecrets: Show sensitive secrets along with TOTP/HOTP, defaults to False
    :type showsecrets: bool, optional
    :param timeserver: Use specific time server instead of choosing from list of known public, defaults to None
    :type timeserver: str | None, optional
    :param endtimer: Show a timer with the expiration time of codes, defaults to True
    :type endtimer: bool, optional
    :param showerr: Show descriptive errors even if they could include sensitive information, defaults to False
    :type showerr: bool, optional
    :param filterterm: Filter the secrets using this term using fuzzy matching unless exact is True, defaults to None
    :type filterterm: str | None, optional
    :param clearscreen: Clear screen after all secrets expire, defaults to True
    :type clearscreen: bool, optional
    :param exact: Disable fuzzy matching on filter term, defaults to False
    :type exact: bool, optional
    :param mintime: THe minimum time left on strings to use if 'now' is False, defaults to 12
    :type mintime: int, optional
    :return: Nothing
    :rtype: None
    """
    init(timeservers)
    secrets = SearchSecrets(filterterm, secrets, exact=exact)
    secrets = FilterSecrets(secrets)
    names = sorted(secrets.keys(), key=str.casefold)
    names = [x for x in names if "totp" in secrets[x]]
    names = list(secrets.keys())
    if len(names) == 0:
        printerr("No matching secrets found!")
        return None
    rt = RemainingTime()
    logger.debug(f"{rt=} {mintime=} {now=}")
    if rt < mintime and now is False:
        Countdown(f"Waiting for new codes:", rt + 1)
    tfaresults = TFAResults(
        showsecrets=showsecrets,
        showerr=showerr,
        endtimer=endtimer,
        clearscreen=clearscreen,
        mintime=mintime,
        now=now,
    )
    for name in names:
        secretdata = secrets[name]
        totp = secretdata.get("totp", "")
        user = secretdata.get("user", "")
        password = secretdata.get("password", "") if secretdata.get("password", "") is not None else ""
        url = secretdata.get("url", "") if secretdata.get("url", "") is not None else ""
        code = ""
        nextcode = ""
        try:
            if totp:
                codes = multitotpcalc(totp, codecount=2)
                thiscode = codes[0]
                code = thiscode.code
                thenextcode = codes[1]
                nextcode = thenextcode.code
            result = TFAResult(
                name=name,
                totp=fix_b32decode_pad(totp),
                code=str(code),
                nextcode=str(nextcode),
                user=user,
                password=password,
                url=url,
                valid=True,
                error=None,
                showsecrets=showsecrets,
                showerr=showerr,
            )
            tfaresults[result] = ...
        except (Invalid2FACodeError, NoInternetError, NTPError, NTPInvalidServerResponseError) as ivce:
            result = TFAResult(
                name=name,
                totp=fix_b32decode_pad(totp),
                code=str(code),
                nextcode=str(nextcode),
                user=user,
                password=password,
                url=url,
                valid=False,
                error=ivce,
                showsecrets=showsecrets,
                showerr=showerr,
            )
            tfaresults[result] = ...
            continue
    return tfaresults.ShowCodes()


def multitotp_continuous(
    secrets: dict,
    timelimit: int = 90,
    showsecrets: bool = False,
    # timeserver: str | None = None,
    showerr: bool = False,
    filterterm: str | None = None,
    clearscreen: bool = True,
    exact: bool = False,
    timeservers: list | None = None,
) -> None:
    """
    _summary_

    :param secrets: Dictionary of secrets, usually from the config
    :type secrets: dict
    :param timelimit: Continuous code display time, defaults to 90
    :type timelimit: int, optional
    :param showsecrets: _description_, defaults to False
    :type showsecrets: bool, optional
    :param showerr: _description_, defaults to False
    :type showerr: bool, optional
    :param filterterm: _description_, defaults to None
    :type filterterm: str | None, optional
    :param clearscreen: _description_, defaults to True
    :type clearscreen: bool, optional
    :param exact: _description_, defaults to False
    :type exact: bool, optional
    :raises KILLED: _description_
    """
    init(timeservers)
    tstart = time.time()
    remaining = RemainingTime()
    try:
        while time.time() - tstart < timelimit:
            remaining = multitotp(
                secrets,
                now=True,
                showsecrets=showsecrets,
                # timeserver=timeserver,
                endtimer=False,
                showerr=showerr,
                filterterm=filterterm,
                clearscreen=clearscreen,
                exact=exact,
            )
            if remaining is None:
                return
            sessionremtime = timelimit - (time.time() - tstart)
            if remaining > sessionremtime and remaining:
                sessionremtime = remaining
            if IsIPython():
                DoubleCountdown(
                    s1="Codes Expire in: ",
                    t1=remaining,
                    s2="Session expiring in: ",
                    t2=sessionremtime,
                    killonfirst=True,
                )
            else:
                codesbar = ProgBar(
                    msg="Codes Expire",
                    timertime=remaining,
                    fixedbartime=30.0,
                )
                sessionbar = ProgBar(
                    msg="Session Expires",
                    timertime=sessionremtime,
                    fixedbartime=timelimit,
                )
                bars = CountdownBars([codesbar, sessionbar], systime=True)
                while bars.Completed is False:
                    bars.update()
                    time.sleep(bars.freq)
            if clearscreen:
                clear_output_ex()
            time.sleep(1)
        if clearscreen:
            clear_output_ex()
        printok("MFAwesome code session finished!")
    except KeyboardInterrupt as e:
        sessionremtime = sessionremtime - (time.time() - tstart)
        raise KILLED(f"Got keyboard interrupt with {remaining:0.1f}s on codes remaining, {sessionremtime:0.1f}s on session!") from e
    finally:
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()
