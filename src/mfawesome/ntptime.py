from __future__ import annotations

import contextlib
import copy
import logging
import os
import random
import socket
import struct
import time
import traceback
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Self

# from mfawesome.config import LoadNTPServers, LocateConfig, ReadConfigFile
from mfawesome.exception import (
    ConfigNotFoundError,
    MFAwesomeError,
    NoInternetError,
    NTPAllServersFailError,
    NTPError,
    NTPInvalidServerResponseError,
    NTPRequestError,
    NTPTimeoutError,
)
from mfawesome.utils import PrintStack, RunOnlyOnce, TimeoutD, ValidateIP, colorstring, printcrit, printdbg, printerr, printok, printwarn

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger("mfa")


class NTPTime:
    """Uses NTPv3."""

    NOINTERNET = False
    # FAILED_SERVERS: ClassVar = set()
    TOTALREQUESTCOUNT = 0
    REF_TIME_1970 = 2208988800
    PUBLIC_TIME_SERVERS: ClassVar = ["time.google.com", "time.cloudflare.com", "time.windows.com", "time.nist.gov"]

    LEAP_TABLE: ClassVar = {
        0: "no warning",
        1: "last minute of the day has 61 seconds",
        2: "last minute of the day has 59 seconds",
        3: "unknown (clock unsynchronized)",
    }

    MODE_TABLE: ClassVar = {
        0: "reserved",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "reserved for NTP control messages",
        7: "reserved for private use",
    }

    @staticmethod
    def toSigned8(n):
        n = n & 0xFF
        return n | (-(n & 0x80))

    @staticmethod
    def ConvertPrecision(i):
        return (i >> 16) + ((i & 0xFFFF) / 0xFFFF)

    @staticmethod
    def ConvertRefID(i, peer_clock_stratum):
        match peer_clock_stratum:
            case 1:
                try:
                    return struct.pack("!I", i).decode()
                except UnicodeDecodeError as e:
                    raise NTPInvalidServerResponseError(
                        f"Converting the reference id failed - likely an invalid response from the NTP server.  refid: {i}  {peer_clock_stratum=}",
                    ) from e
            case 2:
                octs = []
                octs.append(str(i >> 24))
                octs.append(str((i >> 16) & 0xFF))
                octs.append(str((i & 0xFFFF) >> 8))
                octs.append(str(i & 0xFF))
                return ".".join(octs)
            case _:
                return None

    @staticmethod
    def TimeToStr(ts):
        """
        ts is equivalent to time.time() value
        """
        return time.strftime(
            f"%Y-%m-%d %I:%M:%S{str(round(ts % 1, 6))[1:]} %p %Z",
            time.strptime(time.ctime(ts)),
        )

    @staticmethod
    def ConvertTS(ts):
        if ts == 0:
            return None, None
        time_time_equivalent = ((ts >> 32) - NTPTime.REF_TIME_1970) + ((ts & 0xFFFFFFFF) / 0xFFFFFFFF)
        stime = NTPTime.TimeToStr(time_time_equivalent)
        return time_time_equivalent, stime

    @staticmethod
    def MakeNTPRequest(tserver: str, timeout: float = -1, port: int = 123) -> tuple[bytes, str, float]:
        @TimeoutD(timeout, NoInternetError(message="Unresponsive server or bad network connection"))
        def _MakeNTPRequest(tserver: str, timeout: float = -1, port: int = 123) -> tuple[bytes, str, float]:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if timeout > 0:
                client.settimeout(timeout)
            data = b"\x1b" + 39 * b"\0" + NTPTime.GetLocalTxTimeBytes()
            tstart = time.time()
            client.sendto(data, (tserver, port))
            rdata, address = client.recvfrom(1024)
            totaltime = time.time() - tstart
            client.close()
            return rdata, address[0], totaltime

        return _MakeNTPRequest(tserver=tserver, timeout=timeout, port=port)

    @staticmethod
    def GetLocalTxTimeBytes() -> bytes:
        tlocal = time.time()
        tint = int(tlocal - (tlocal % 1)) + NTPTime.REF_TIME_1970
        tlow = int((tlocal % 1) * 0xFFFFFFFF)
        return struct.pack("!II", tint, tlow)

    @staticmethod
    def RequestTimeFromNtp(
        timeservers: list = [],
        timeout: float = 1.0,
        maxtimeservers: int = 5,
    ) -> str:
        def cycle_time_servers(timeservers: list) -> Generator[str]:
            random.shuffle(timeservers)
            yield from timeservers

        if NTPTime.NOINTERNET:
            logger.debug(f"The NoInternet flag is set on NTPTime, returning None")
            return None
        data = None

        for tserver in cycle_time_servers(timeservers=timeservers):
            if maxtimeservers <= NTPTime.TOTALREQUESTCOUNT:
                NTPTime.NOINTERNET = True
                break
            try:
                NTPTime.TOTALREQUESTCOUNT += 1
                logger.debug(f"NTPTime total requests: {NTPTime.TOTALREQUESTCOUNT}.  Attempting time sever {tserver} with timeout {timeout}...")
                data, address, totaltime = NTPTime.MakeNTPRequest(tserver, timeout)

                logger.debug(f"Got time from server {tserver} {address} with length {len(data)} in {(totaltime):.2f}s")
            except (socket.gaierror, TimeoutError, NoInternetError) as e:
                if isinstance(e, socket.gaierror):
                    logger.warning(f"socket.gaierror indicates DNS or general network connection failure")
                logger.debug(f"Error contacting timeserver {tserver}: {e!r} with timeout {timeout}")
                continue
            else:
                return data
        raise NTPAllServersFailError("No time server was able to be successfully contacted - check network connection")

    @staticmethod
    def GetNTPTimeTuple(
        timeservers: list,
        timeout: float = 1.0,
    ) -> tuple[
        str,
        Any,
        str,
        Any,
        Any,
        Any,
        Any,
        Any,
        str | None,
        Any | None,
        str | None,
        Any | None,
        str | None,
        Any | None,
        str | None,
        Any | None,
        str | None,
    ]:
        (
            flags,
            peer_clock_stratum,
            peer_polling_interval,
            peer_clock_precision,
            root_delay,
            root_dispersion,
            ref_id,
            ref_ts,
            origin_ts,
            rcv_ts,
            tx_ts,
        ) = struct.unpack(
            "!BBBbIIIQQQQ",
            NTPTime.RequestTimeFromNtp(
                timeout=timeout,
                timeservers=timeservers,
            ),
        )
        leap_indicator = NTPTime.LEAP_TABLE[flags >> 6]
        version_number = (flags >> 3) & 7
        mode = NTPTime.MODE_TABLE[flags & 7]
        peer_polling_interval = 2**peer_polling_interval
        peer_clock_precision = 2 ** NTPTime.toSigned8(peer_clock_precision)
        root_delay = NTPTime.ConvertPrecision(root_delay)
        root_dispersion = NTPTime.ConvertPrecision(root_dispersion)
        ref_id = NTPTime.ConvertRefID(ref_id, peer_clock_stratum)
        ref_ts, ref_ts_str = NTPTime.ConvertTS(ref_ts)
        origin_ts, origin_ts_str = NTPTime.ConvertTS(origin_ts)
        rcv_ts, rcv_ts_str = NTPTime.ConvertTS(rcv_ts)
        tx_ts, tx_ts_str = NTPTime.ConvertTS(tx_ts)
        return (
            leap_indicator,
            version_number,
            mode,
            peer_clock_stratum,
            peer_polling_interval,
            peer_clock_precision,
            root_delay,
            root_dispersion,
            ref_id,
            ref_ts,
            ref_ts_str,
            origin_ts,
            origin_ts_str,
            rcv_ts,
            rcv_ts_str,
            tx_ts,
            tx_ts_str,
        )

    @dataclass
    class NTPTimestamp:  # noqa: D106
        leap_indicator: str
        version_number: int
        mode: str
        peer_clock_stratum: int
        peer_polling_interval: str
        peer_clock_precision: int
        root_delay: float
        root_dispersion: float
        ref_id: str
        ref_ts: float
        ref_ts_str: str
        origin_ts: float
        origin_ts_str: str
        rcv_ts: float
        rcv_ts_str: str
        tx_ts: float
        tx_ts_str: str

    def __init__(
        self,
        timeservers: list | str | None = None,
        timeout: float = 1.0,
        maxage: float = 3600,
        localtime_max_deviation: float = 0.2,
        updatenow: bool = True,
    ) -> None:
        self.timeout = timeout
        self.localtime_max_deviation = localtime_max_deviation
        self.localtime_ok = False
        self.systemdeviation = None
        self.__timeservers = []
        self.timeservers = timeservers
        self.TimeTuple = None
        self.ts = None
        self.systemtime = None  # snapped at the same time as self.ts from the timeserver
        self.NTPSuccess = False
        self.maxage = maxage
        self.stamp_time = -1

        if updatenow:
            self.UpdateTime()
        # logger.debug(f"Here's the timeservers used (total of {len(self.timeservers)}, showing max 5): {self.timeservers[0:5]=}")

    @property
    def timeservers(self) -> list:
        return self.__timeservers

    @timeservers.setter
    def timeservers(self, val: list | str | None) -> None:
        # pass an empty list if you want to default to local time
        # pass "systemtime" to use local system time
        if val in [["systemtime"], "systemtime"] or val is None:
            self.__timeservers = []
        self.__timeservers = val
        if isinstance(self.__timeservers, list):
            pass
        elif isinstance(self.__timeservers, str):
            self.__timeservers = self.__timeservers.split(":")

        elif self.__timeservers is None:
            if env_timesersvers := os.environ.get("NTP_SERVERS"):
                self.__timeservers = env_timesersvers.split(":")
            else:
                self.__timeservers = NTPTime.PUBLIC_TIME_SERVERS
        if not isinstance(self.__timeservers, list):
            raise TypeError(f"Invalid type for NTPTime.timeservers: {type(self.__timeservers)}")
        self.__timeservers = list(filter(lambda item: item is not None, self.__timeservers))

    def UpdateTime(self, force: bool = False, timeservers: list | str | None = None) -> None:
        self.timeservers = timeservers

        @RunOnlyOnce("NoTimeServersWarning")
        def NoTimeServersWarning() -> None:
            printwarn("WARNING:  No time servers specified, falling back to local time")

        @RunOnlyOnce("NoInternetDebug")
        def NoInternetDebug() -> None:
            printwarn("NTPTime NOINTERNET flag is already set, skipping time lookup")

        if len(self.timeservers) == 0:
            NoTimeServersWarning()
            self.ts = time.time()
            return
        if NTPTime.NOINTERNET:
            NoInternetDebug()
            self.NTPSuccess = False
            self.ts = time.time()
            return

        if not force:
            if abs(time.time() - self.stamp_time) > 3600:
                logger.debug(f"Last NTP update is stale by more than 1 hour, updating...")
                self.localtime_ok = False
            if self.localtime_ok:
                self.NTPSuccess = True
                self.ts = time.time()  # - devn
                return
        try:
            timetuple = NTPTime.GetNTPTimeTuple(timeservers=self.timeservers, timeout=self.timeout)
        except (NTPAllServersFailError, NoInternetError) as e:
            NTPTime.NOINTERNET = True
            if isinstance(e, NoInternetError):
                printwarn(f"WARNING: {e.message} - Falling back to local time!")
            elif isinstance(e, NTPAllServersFailError):
                printwarn(f"WARNING: Failed get network time or no timeservers specified - Falling back to local time!")
            logger.debug(f"Failed to contact ntp server, falling back to local time {e!r}")
            self.NTPSuccess = False
            self.ts = time.time()
        else:
            self.TimeTuple = NTPTime.NTPTimestamp(*timetuple)
            self.systemdeviation = abs(time.time() - self.TimeTuple.rcv_ts)
            tts = self.TimeTuple.rcv_ts if self.TimeTuple.rcv_ts is not None else 0.0
            percent_diff = f"{(self.systemdeviation / self.localtime_max_deviation)*100:.2f}%"
            # logger.debug(f"{tts=:0.1f}  {time.time()=:0.1f}  {self.systemdeviation=:0.4f}  {self.localtime_max_deviation=} percent_diff={percent_diff}")
            if self.TimeTuple.rcv_ts:
                self.NTPSuccess = True
                self.ts = self.TimeTuple.rcv_ts
                if abs(time.time() - self.ts) <= self.localtime_max_deviation:
                    self.localtime_ok = True
                    # logger.debug(f"Local time is good.  Deviation: {self.systemdeviation:0.4f} < Max Deviation {self.localtime_max_deviation} ({percent_diff} of allowed max deviation)")
                else:
                    self.localtime_ok = False
                    logger.debug(f"Local time is off.  Deviation: {self.systemdeviation} > Max Deviation {self.localtime_max_deviation} ({percent_diff}%)")
        self.stamp_time = time.time()

    @property
    def Time(self) -> str:
        self.UpdateTime()
        return NTPTime.TimeToStr(self.ts)

    def __str__(self) -> str:
        """
        _summary_

        :return: _description_
        :rtype: str
        """
        return self.Time

    def __repr__(self) -> str:
        """
        _summary_

        :return: _description_
        :rtype: str
        """
        return self.Time
