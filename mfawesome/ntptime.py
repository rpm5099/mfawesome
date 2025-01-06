from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import random
import socket
import statistics
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from mfawesome.exception import (
    NTPError,
    NTPInvalidServerResponseError,
    NTPTimeoutError,
)
from mfawesome.utils import TimeoutD

logger = logging.getLogger("mfa")

LOCAL_TZINFO = datetime.now().astimezone().tzinfo


def ReverseDNS(ip, dnstimeout=0.5, nameservers=None):
    try:
        import dns

        myresolver = dns.resolver.Resolver(configure=True)
        if nameservers:
            myresolver.nameservers = nameservers
        myresolver.timeout = dnstimeout
        myresolver.lifetime = dnstimeout
        ipr = dns.reversename.from_address(ip)
        ptranswsers = myresolver.resolve(ipr, "PTR")
    except ModuleNotFoundError as e:
        logger.debug("dnspython is not installed, skipping reverse dns")
        return []
    else:
        return ", ".join([str(x).strip(".") for x in ptranswsers.rrset])


REF_TIME_1970 = 2208988800

LEAP_TABLE: dict = {
    0: "no warning",
    1: "last minute of the day has 61 seconds",
    2: "last minute of the day has 59 seconds",
    3: "unknown (clock unsynchronized)",
}

MODE_TABLE: dict = {
    0: "reserved",
    1: "symmetric active",
    2: "symmetric passive",
    3: "client",
    4: "server",
    5: "broadcast",
    6: "reserved for NTP control messages",
    7: "reserved for private use",
}


@dataclass
class NTPRaw:
    flags: int
    peer_clock_stratum: int
    peer_polling_interval: int
    peer_clock_precision: int
    root_delay: int
    root_dispersion: int
    ref_id: int
    ref_ts: int
    origin_ts: int
    rcv_ts: int
    tx_ts: int


@dataclass
class NTPTimestamp:
    timeserver: str
    timeserver_ip: str
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
    origin_ts: float  # T1 - system tx time sent to NTP server (should match sys_tx below)
    origin_ts_str: str
    rcv_ts: float  # T2 - receive time at NTP server
    rcv_ts_str: str
    tx_ts: float  # T3 - departure time from NTP server
    tx_ts_str: str
    sys_tx: float  # also T1 - system tx time sent to NTP server
    sys_tx_str: str
    sys_rcv: float  # T4 - system time on recieve
    sys_rcv_str: str
    round_trip_time: float
    round_trip_time_ms: int
    offset: float
    offset_ms: int
    systemtime: float
    systemtime_str: str
    corrected_time: float
    corrected_time_datetime: datetime
    corrected_time_str: str
    ntpraw: NTPRaw


def toSigned8(n):
    n = n & 0xFF
    return n | (-(n & 0x80))


def ConvertPrecision(i):
    return (i >> 16) + ((i & 0xFFFF) / 0xFFFF)


def ConvertRefIDX(i, peer_clock_stratum) -> str:
    """
    Valid reference id's
    | GOES | Geosynchronous Orbit Environment Satellite               |
    | GPS  | Global Position System                                   |
    | GAL  | Galileo Positioning System                               |
    | PPS  | Generic pulse-per-second                                 |
    | IRIG | Inter-Range Instrumentation Group                        |
    | WWVB | LF Radio WWVB Ft. Collins, CO 60 kHz                     |
    | DCF  | LF Radio DCF77 Mainflingen, DE 77.5 kHz                  |
    | HBG  | LF Radio HBG Prangins, HB 75 kHz                         |
    | MSF  | LF Radio MSF Anthorn, UK 60 kHz                          |
    | JJY  | LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz       |
    | LORC | MF Radio LORAN C station, 100 kHz                        |
    | TDF  | MF Radio Allouis, FR 162 kHz                             |
    | CHU  | HF Radio CHU Ottawa, Ontario                             |
    | WWV  | HF Radio WWV Ft. Collins, CO                             |
    | WWVH | HF Radio WWVH Kauai, HI                                  |
    | NIST | NIST telephone modem                                     |
    | ACTS | NIST telephone modem                                     |
    | USNO | USNO telephone modem                                     |
    | PTB  | European telephone modem
    """
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


def ConvertRefID(idi: int) -> str:
    def fallback(ip):
        try:
            return f"{ip}: {ReverseDNS(ip)}"
        except Exception as e:
            return ip

    ip = str(ipaddress.ip_address(idi))
    if ip in NTPIPS:
        return NTPIPS[ip]
    return fallback(ip)


def seconds2ms(t):
    return int(round(t * 1000, 0))


def Time2Datetime(ts) -> datetime:
    return datetime.fromtimestamp(ts, tz=LOCAL_TZINFO)


def Time2Str(ts):
    """
    Ts is equivalent to time.time() value
    """
    return Time2Datetime(ts).strftime(f"%Y-%m-%d %I:%M:%S.%f %p")


def ConvertTS(ts):
    time_time_equivalent = float(((ts >> 32) - REF_TIME_1970) + ((ts & 0xFFFFFFFF) / Decimal(0xFFFFFFFF)))
    stime = Time2Str(time_time_equivalent)
    return time_time_equivalent, stime


def NTP_Float2Bytes(ts) -> bytes:
    tint, tlow = divmod(ts, 1)
    tint = int(tint) + REF_TIME_1970
    tlow = int(tlow * 0xFFFFFFFF)
    ntp64 = (tint << 32) + tlow
    return ntp64, struct.pack("!II", tint, tlow)


def RequestTime(timeserver: str, timeout: float = -1, port: int = 123) -> tuple[bytes, str, float]:
    @TimeoutD(timeout, NTPTimeoutError(message=f"Unresponsive time server ({timeserver}) or bad network connection"))  # type: ignore
    def _RequestTime(tserver: str, timeout: float = -1, port: int = 123) -> tuple[bytes, str, float]:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if timeout > 0:
            client.settimeout(timeout)
        sys_tx = time.time()
        __sys_tx_int, data = NTP_Float2Bytes(sys_tx)
        data = b"\x1b" + 39 * b"\0" + data
        client.sendto(data, (tserver, port))
        rdata, address = client.recvfrom(1024)
        sys_rcv = time.time()
        client.close()
        return (rdata, address[0], sys_tx, sys_rcv)

    try:
        logger.debug(f"Attempting time sever {timeserver} with timeout {timeout}...")
        data, ipaddress, sys_tx, sys_rcv = _RequestTime(timeserver, timeout, port)
        round_trip_time = sys_rcv - sys_tx

        logger.debug(f"Got time from server {timeserver} {ipaddress} with length {len(data)} with round trip {(round_trip_time):.2f}s")
    except (socket.gaierror, TimeoutError, NTPTimeoutError) as e:
        if isinstance(e, socket.gaierror):
            raise NTPTimeoutError(f"socket.gaierror indicates DNS or general network connection failure") from e
        raise NTPTimeoutError(f"Error contacting timeserver {timeserver}: {e!r} with timeout {timeout}") from e
    else:
        return data, ipaddress, sys_tx, sys_rcv


def NTPTime(
    timeserver: str,
    timeout: float = 3.0,
) -> NTPTimestamp:
    data, ipaddress, sys_tx, sys_rcv = RequestTime(timeserver=timeserver, timeout=timeout)  # type: ignore
    ntpraw = NTPRaw(*struct.unpack("!BBBbIIIQQQQ", data))  # type: ignore
    leap_indicator = LEAP_TABLE[ntpraw.flags >> 6]
    version_number = (ntpraw.flags >> 3) & 7
    mode = MODE_TABLE[ntpraw.flags & 7]
    peer_polling_interval = 2**ntpraw.peer_polling_interval
    peer_clock_precision = 2 ** toSigned8(ntpraw.peer_clock_precision)
    root_delay = ConvertPrecision(ntpraw.root_delay)
    root_dispersion = ConvertPrecision(ntpraw.root_dispersion)
    ref_id = ConvertRefID(ntpraw.ref_id)
    # ref_id = ConvertRefID(ntpraw.ref_id, ntpraw.peer_clock_stratum)
    ref_ts, ref_ts_str = ConvertTS(ntpraw.ref_ts)
    origin_ts, origin_ts_str = ConvertTS(ntpraw.origin_ts)
    rcv_ts, rcv_ts_str = ConvertTS(ntpraw.rcv_ts)
    tx_ts, tx_ts_str = ConvertTS(ntpraw.tx_ts)
    if origin_ts != sys_tx:
        raise NTPError("The NTP response origin transmit time does NOT match the time sent to the NTP server - this is a security issue")
    round_trip_time = sys_rcv - sys_tx
    offset = ((rcv_ts - sys_tx) + (tx_ts - sys_rcv)) / 2
    systemtime = time.time()
    corrected_time = systemtime + offset

    return NTPTimestamp(
        timeserver,
        ipaddress,
        leap_indicator,
        version_number,
        mode,
        ntpraw.peer_clock_stratum,
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
        sys_tx,
        Time2Str(sys_tx),
        sys_rcv,
        Time2Str(sys_rcv),
        round_trip_time,
        seconds2ms(round_trip_time),
        offset,
        seconds2ms(offset),
        systemtime,
        Time2Str(systemtime),
        corrected_time,
        Time2Datetime(systemtime),
        Time2Str(corrected_time),
        ntpraw,
    )


def PooledNTPTime(pool: int | list | set | tuple = 10, timeout: float = 1.0):
    def Task(server, timeout):
        try:
            result = NTPTime(server, timeout)
        except NTPError as e:
            return e
        else:
            return result

    if not pool:
        logger.debug(f"Invalid value for timeserver pool passed to PooledNTPTime, ignoring.  {pool=}")
        pool = 10

    if isinstance(pool, int):
        pool = random.sample(list(NTPSERVERS["NTPSERVERS"].keys()), pool)

    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(Task, server, timeout) for server in pool]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def systime_offset(pool: int | list | set | tuple = 10, timeout: float = 1.0):
    ntptimes = PooledNTPTime(pool, timeout)
    offsets = [x.offset for x in ntptimes if isinstance(x, NTPTimestamp)]
    failed = [repr(x) for x in ntptimes if isinstance(x, Exception)]
    if not offsets:
        raise NTPError(f"No NTP server in the pool could be contacted.  Example Error: {failed[0]!r}")
    if len(offsets) == 1:
        return offsets[0]
    stdev = statistics.stdev(offsets)
    mean = statistics.mean(offsets)
    percent_stdev = (stdev / mean) * 100
    if percent_stdev > 200:
        raise NTPError(f"Standard deviation is {percent_stdev:.3f}% of mean - one or more time servers may be inaccurate")
    return -mean


def timestamp(pool: int | list | set | tuple = 10, timeout: float = 1.0):
    ntptimes = PooledNTPTime(pool, timeout)
    times = [x.corrected_time for x in ntptimes if isinstance(x, NTPTimestamp)]
    failed = [repr(x) for x in ntptimes if isinstance(x, Exception)]
    if not times:
        raise NTPError(f"No NTP server in the pool could be contacted.  Example Error: {failed[0]!r}")
    if len(times) == 1:
        return times[0]
    stdev = statistics.stdev(times)
    mean = statistics.mean(times)
    percent_stdev = (stdev / mean) * 100
    if percent_stdev > 0.01:
        raise NTPError(f"Standard deviation is {percent_stdev:.3f}% of mean - one or more time servers may be inaccurate")
    return mean


def timestamp_str(pool: int | list | set | tuple = 10, timeout: float = 1.0):
    return Time2Str(timestamp(pool, timeout))


def MakeIPDict(ntps):
    ntpips = {}
    for k, v in ntps.items():
        for ip in v:
            ntpips[ip] = k
    return ntpips


def ndelta(n: float) -> str:
    udelta = "\u0394"
    if n == 0:
        posneg = ""
    elif n > 0:
        posneg = "+"
    else:
        posneg = "-"
    return f"{udelta} {posneg}{abs(n)}"


class CorrectedTime:
    systimeoff: float | None = None

    def __init__(self, timeservers: int | list | tuple | set = 10):
        self._timeservers = timeservers
        self._time = None
        self._systime = None
        self._init_time = time.time()

    @property
    def time(self):
        if CorrectedTime.systimeoff is None:
            CorrectedTime.systimeoff = systime_offset(pool=self._timeservers)
        self._systime = time.time()
        self._time = self._systime - CorrectedTime.systimeoff
        return self._time

    @property
    def init_time(self):
        if CorrectedTime.systimeoff is None:
            return self._init_time
        return self._init_time - CorrectedTime.systimeoff

    @property
    def timeservers(self):
        return self._timeservers

    @timeservers.setter
    def timeservers(self, newtimeservers):
        self._timeservers = newtimeservers
        CorrectedTime.systimeoff = systime_offset(pool=self._timeservers)

    def resync(self) -> None:
        CorrectedTime.systimeoff = systime_offset(pool=self._timeservers)
        self._systime = time.time()
        self._time = self._systime - CorrectedTime.systimeoff

    @staticmethod
    def ts2str(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=LOCAL_TZINFO).strftime("%Y-%m-%d %I:%M:%S.%f %p")

    def __str__(self) -> str:
        return CorrectedTime.ts2str(self._time)

    def __repr__(self) -> str:
        return self.__str__()

    def systimestr(self) -> str:
        return f"System Time: {self.__str__()}"

    def clock(self, n: int = 180):
        green = "\x1b[1m\x1b[32m"
        grey = "\x1b[90m"
        reset = "\x1b[0;0;39m"
        for i in range(n * 5):
            if i % 600 == 0:
                self.resync()
            ts = self.time
            s = f"{green} Corrected Time: {CorrectedTime.ts2str(ts)} {grey} System Time: {CorrectedTime.ts2str(self._systime)} (Offset: {ndelta(round(CorrectedTime.systimeoff, 2))}s) {reset}      "
            print(s, end="\r")
            time.sleep(0.2)


def Clock():
    CorrectedTime().clock()


NTPSERVERS = {
    "NTPSERVERS": {
        "0.amazon.pool.ntp.org": [],
        "0.android.pool.ntp.org": ["69.164.203.231", "50.205.57.38", "104.167.215.195", "159.203.82.102"],
        "0.arch.pool.ntp.org": ["66.85.78.80", "204.93.207.12", "23.111.186.186", "50.251.160.20"],
        "0.askozia.pool.ntp.org": [],
        "0.centos.pool.ntp.org": ["159.203.82.102", "216.31.16.12", "23.142.248.9", "23.149.208.12"],
        "0.debian.pool.ntp.org": ["129.146.193.200", "45.79.214.107", "64.79.100.197", "23.142.248.9"],
        "0.dragonfly.pool.ntp.org": [],
        "0.europe.pool.ntp.org": [],
        "0.fedora.pool.ntp.org": ["104.207.148.118", "104.167.215.195", "104.167.241.253", "23.111.186.186"],
        "0.freebsd.pool.ntp.org": [],
        "0.gentoo.pool.ntp.org": ["135.148.100.14", "74.208.25.46", "50.251.160.20", "104.167.215.195"],
        "0.openbsd.pool.ntp.org": [],
        "0.opensuse.pool.ntp.org": ["45.84.199.136", "104.131.155.175", "50.205.57.38", "173.71.68.71"],
        "0.opnsense.pool.ntp.org": ["96.60.160.227", "149.248.12.167", "44.190.5.123", "50.205.57.38"],
        "0.pfsense.pool.ntp.org": [],
        "0.pool.ntp.org": ["69.89.207.99", "208.67.75.242", "144.202.41.38", "216.229.4.69"],
        "0.ru.pool.ntp.org": ["51.250.107.88", "176.215.178.239", "45.92.177.52", "92.241.18.100"],
        "1.amazon.pool.ntp.org": [],
        "1.android.pool.ntp.org": ["162.159.200.1", "204.2.134.163", "23.150.41.122", "23.150.41.123"],
        "1.arch.pool.ntp.org": ["217.180.209.214", "50.205.57.38", "104.152.220.10", "168.61.215.74"],
        "1.askozia.pool.ntp.org": [],
        "1.centos.pool.ntp.org": ["74.6.168.73", "51.81.226.229", "23.150.41.122", "23.155.40.38"],
        "1.debian.pool.ntp.org": ["51.81.226.229", "161.35.230.200", "72.30.35.89", "23.155.40.38"],
        "1.europe.pool.ntp.org": ["45.92.177.52", "94.143.139.219", "62.108.36.235", "178.16.23.50"],
        "1.fedora.pool.ntp.org": ["23.150.41.122", "23.150.41.123", "72.30.35.89", "142.202.190.19"],
        "1.freebsd.pool.ntp.org": ["51.81.226.229", "23.155.40.38", "50.218.103.254", "207.246.65.226"],
        "1.gentoo.pool.ntp.org": [],
        "1.north-america.pool.ntp.org": ["161.35.230.200", "66.42.71.197", "96.245.170.99", "45.56.66.53"],
        "1.openbsd.pool.ntp.org": ["45.55.58.103", "23.150.40.242", "162.159.200.1", "192.155.94.72"],
        "1.opensuse.pool.ntp.org": ["71.123.46.185", "50.205.57.38", "152.70.159.102", "66.228.58.20"],
        "1.opnsense.pool.ntp.org": [],
        "1.pfsense.pool.ntp.org": ["45.55.58.103", "51.81.226.229", "45.79.111.114", "142.202.190.19"],
        "1.pool.ntp.org": ["155.248.196.28", "45.83.234.123", "135.134.111.122", "72.30.35.89"],
        "1.ru.pool.ntp.org": ["188.246.226.6", "5.178.87.93", "162.159.200.1", "80.93.187.13"],
        "1.smartos.pool.ntp.org": [],
        "2.amazon.pool.ntp.org": ["2600:3c03::f03c:91ff:fe3e:c3bb", "2602:feda:30:ae86:2fc:98ff:fecf:fe94", "2602:ff06:725:100::123", "2603:c020:0:8369:feed:feed:feed:feed"],
        "2.android.pool.ntp.org": ["2604:2dc0:101:200::e01", "2607:f1c0:f06b:5000::3", "2603:c024:c005:a600:efb6:d213:cad8:251d", "2001:470:e114::123"],
        "2.arch.pool.ntp.org": [
            "149.248.12.167",
            "172.234.37.140",
            "216.31.17.12",
            "135.148.100.14",
            "2600:3c02:e001:1d00::123:0",
            "2001:418:8405:4002::3",
            "2601:18a:8081:3600:a923:2e66:e3d2:8c95",
            "2603:c020:0:8369::bad:babe",
        ],
        "2.askozia.pool.ntp.org": ["2600:4040:e0da:f000::cbb9:201a", "2604:2dc0:100:380e::", "2a01:7e03::f03c:92ff:fe8c:f7c9", "2600:1700:5a0f:ee00::314:1b"],
        "2.centos.pool.ntp.org": ["83.147.242.172", "173.161.33.165", "212.227.240.160", "45.33.53.84", "2602:291:69::8", "2604:a880:400:d0::83:2002", "2a05:dfc1:cd4::123", "2604:2dc0:101:200::151"],
        "2.debian.pool.ntp.org": ["204.93.207.12", "168.235.86.33", "142.202.190.19", "99.28.14.242"],
        "2.dragonfly.pool.ntp.org": ["2602:f9bd:80:100::a", "2603:c020:6:b900:ed2f:b442:fee7:d9b9", "2001:470:e114::d6:c5", "2605:6400:84e1::123"],
        "2.europe.pool.ntp.org": [
            "212.41.8.158",
            "185.233.107.180",
            "62.108.36.235",
            "195.90.182.235",
            "2001:41d0:304:200::199e",
            "2a02:c206:2212:6198::1010",
            "2a02:2f04:a0e:9199:99::3",
            "2a02:c6c1:c:207::13",
        ],
        "2.fedora.pool.ntp.org": [
            "172.235.32.243",
            "168.235.86.33",
            "108.61.215.221",
            "155.248.196.28",
            "2600:4040:e0da:f000::cbb9:201a",
            "2604:2dc0:202:300::140d",
            "2001:470:b:22d::123",
            "2600:3c01:e000:7e6::123",
        ],
        "2.freebsd.pool.ntp.org": ["204.2.134.163", "104.194.8.227", "99.28.14.242", "207.246.65.226", "2604:4300:a:299::164", "2a05:dfc1:cd4::123", "2604:2dc0:101:200::b9d", "2001:559:2be:3::1001"],
        "2.gentoo.pool.ntp.org": ["2607:f1c0:f06b:5000::3", "2001:470:e114::d6:c5", "2602:f95b:2::1", "2a01:4ff:1f0:c33f::1"],
        "2.netbsd.pool.ntp.org": ["2602:2eb:2:95:1234:5678:9abc:def0", "2a05:dfc1:cd4::123", "2602:291:69::8", "2602:f95b:2::1"],
        "2.openbsd.pool.ntp.org": [
            "72.46.53.234",
            "216.229.4.66",
            "5.78.62.36",
            "155.248.196.28",
            "2a01:7e03::f03c:92ff:fe8c:f7c9",
            "2602:f9bd:80:100::a",
            "2001:470:e114::d6:12",
            "2603:c020:0:8369:607:e532:d534:7109",
        ],
        "2.opensuse.pool.ntp.org": ["96.245.170.99", "144.202.66.214", "45.83.234.123", "23.186.168.1"],
        "2.pfsense.pool.ntp.org": ["45.83.234.123", "192.48.105.15", "216.229.4.69", "67.217.246.204"],
        "2.pool.ntp.org": ["2607:f1c0:f014:9e00::1", "2001:19f0:1590:5123:1057:a11:da7a:1", "2606:82c0:22::e", "2607:f1c0:f04e:fd00::1"],
        "2.ru.pool.ntp.org": ["5.178.87.94", "212.113.99.6", "194.67.201.38", "86.110.190.186", "2a03:6f00:a::2f7f", "2a00:b700:3::288", "2001:67c:205c:11::84", "2a03:aa00::136:55"],
        "2.smartos.pool.ntp.org": ["83.147.242.172", "67.217.246.204", "192.48.105.15", "134.215.155.177"],
        "3.amazon.pool.ntp.org": ["129.250.35.250", "66.205.249.28", "99.28.14.242", "23.94.221.138"],
        "3.android.pool.ntp.org": ["173.249.203.72", "23.142.248.8", "15.204.87.223", "208.67.75.242"],
        "3.arch.pool.ntp.org": [],
        "3.askozia.pool.ntp.org": [],
        "3.centos.pool.ntp.org": ["216.31.17.12", "162.159.200.123", "129.250.35.250", "172.233.153.85"],
        "3.debian.pool.ntp.org": [],
        "3.dragonfly.pool.ntp.org": ["66.205.249.28", "216.31.17.12", "162.159.200.123", "74.208.117.38"],
        "3.europe.pool.ntp.org": ["158.227.98.15", "85.254.217.5", "178.239.19.57", "91.206.16.3"],
        "3.fedora.pool.ntp.org": ["192.245.12.21", "162.159.200.123", "23.186.168.2", "66.42.86.174"],
        "3.freebsd.pool.ntp.org": ["208.67.72.50", "99.28.14.242", "172.234.37.140", "129.250.35.250"],
        "3.gentoo.pool.ntp.org": [],
        "3.netbsd.pool.ntp.org": [],
        "3.north-america.pool.ntp.org": [],
        "3.openbsd.pool.ntp.org": ["204.10.18.144", "172.234.37.140", "72.30.35.88", "144.202.62.209"],
        "3.opensuse.pool.ntp.org": ["74.207.240.206", "23.131.160.7", "66.118.230.14", "15.204.87.223"],
        "3.opnsense.pool.ntp.org": [],
        "3.pfsense.pool.ntp.org": ["71.123.46.185", "23.186.168.2", "104.152.220.10", "23.94.221.138"],
        "3.pool.ntp.org": ["69.89.207.99", "104.152.220.10", "192.92.6.30", "64.142.54.12"],
        "3.ru.pool.ntp.org": ["46.160.198.122", "95.165.153.8", "31.131.251.6", "95.79.30.113"],
        "3.smartos.pool.ntp.org": [],
        "asia.pool.ntp.org": ["202.12.97.45", "81.28.7.157", "194.225.150.25", "64.176.168.216"],
        "bonehed.lcs.mit.edu": ["18.26.4.105"],
        "chime1.surfnet.nl": ["192.87.106.2"],
        "clock.isc.org": ["64.62.194.188", "64.62.194.189", "204.93.207.11", "2001:470:1:b07::123:2000", "2001:1838:2000:41b::123:2000", "2001:470:1:b07::123:2001"],
        "clock.nyc.he.net": ["209.51.161.238", "2001:470:0:2c8::2"],
        "clock.sjc.he.net": ["216.218.254.202", "2001:470:0:60f::2"],
        "clock.uregina.ca": ["142.3.100.2"],
        "europe.pool.ntp.org": ["194.58.206.20", "86.52.51.137", "91.206.8.70", "212.45.144.206"],
        "gbg1.ntp.se": ["194.58.203.20", "2a01:3f7:3:1::1"],
        "gbg2.ntp.se": ["194.58.203.148", "2a01:3f7:3:2::1"],
        "hora.roa.es": ["150.214.94.5"],
        "minuto.roa.es": ["150.214.94.10"],
        "mmo1.ntp.se": ["194.58.204.20", "2a01:3f7:4:1::1"],
        "mmo2.ntp.se": ["194.58.204.148", "2a01:3f7:4:2::1"],
        "navobs1.gatech.edu": ["130.207.244.240"],
        "navobs1.oar.net": ["198.30.92.2"],
        "navobs1.wustl.edu": ["128.252.19.1"],
        "north-america.pool.ntp.org": ["104.167.215.195", "212.227.240.160", "23.150.41.123", "99.28.14.242"],
        "now.okstate.edu": ["139.78.97.128"],
        "ntp-galway.hea.net": [],
        "ntp.dianacht.de": ["176.9.157.12", "2a01:4f8:160:430b::2"],
        "ntp.fizyka.umk.pl": ["158.75.5.245"],
        "ntp.ix.ru": ["194.190.168.1", "2001:6d0:ffd4::1"],
        "ntp.mrow.org": ["23.252.63.82", "2604:4080:111d:2010:2ee3:98d7:48eb:60b4"],
        "ntp.neel.ch": ["79.143.250.33", "2001:678:938:300:9780:3b76:7a8a:b9fa"],
        "ntp.nic.cz": ["217.31.202.100", "2001:1488:ffff::100"],
        "ntp.nict.jp": ["133.243.238.244", "133.243.238.163", "133.243.238.243", "133.243.238.164", "61.205.120.130", "2001:ce8:78::2", "2001:df0:232:eea0::fff3", "2001:df0:232:eea0::fff4"],
        "ntp.nsu.ru": ["84.237.48.126"],
        "ntp.qix.ca": ["206.126.112.212", "206.126.112.211", "2620:1f:4000:2::212", "2620:1f:4000:2::211"],
        "ntp.ripe.net": ["193.0.0.229", "2001:67c:2e8:14:ffff::229"],
        "ntp.se": ["194.58.200.20", "2a01:3f7::1"],
        "ntp.shoa.cl": ["190.102.231.152", "190.102.231.147", "200.27.106.116", "200.27.106.115"],
        "ntp.sstf.nsk.ru": ["80.242.83.227"],
        "ntp.time.in.ua": ["62.149.0.30", "2a03:6300:2::123"],
        "ntp.time.nl": ["94.198.159.10", "94.198.159.14", "2a00:d78:0:712:94:198:159:10", "2a00:d78:0:712:94:198:159:14"],
        "ntp.vsl.nl": ["31.223.173.226"],
        "ntp.your.org": ["204.9.54.119"],
        "ntp.yycix.ca": ["192.75.191.6"],
        "ntp0.as34288.net": ["109.233.182.115"],
        "ntp0.nl.uu.net": [],
        "ntp0.ntp-servers.net": [],
        "ntp1.as34288.net": ["109.233.182.116"],
        "ntp1.fau.de": ["131.188.3.221"],
        "ntp1.hetzner.de": ["213.239.239.164", "2a01:4f8:0:a0a1::2:1"],
        "ntp1.inrim.it": ["193.204.114.232", "2001:760:2602::232"],
        "ntp1.jst.mfeed.ad.jp": ["210.173.160.27"],
        "ntp1.net.berkeley.edu": ["169.229.128.134", "2607:f140:ffff:8000:0:8006:0:a"],
        "ntp1.niiftri.irkutsk.ru": ["46.254.241.74"],
        "ntp1.nl.uu.net": ["193.79.237.14"],
        "ntp1.ntp-servers.net": ["195.35.113.80", "185.201.254.21", "116.202.171.176", "185.175.56.95"],
        "ntp1.oma.be": ["193.190.230.65"],
        "ntp1.qix.ca": ["206.126.112.211", "2620:1f:4000:2::211"],
        "ntp1.stratum1.ru": ["89.109.251.21"],
        "ntp1.stratum2.ru": ["176.215.178.239", "45.92.177.52", "92.241.18.100", "51.250.107.88"],
        "ntp1.vniiftri.ru": ["89.109.251.21"],
        "ntp2.fau.de": ["131.188.3.222"],
        "ntp2.hetzner.de": ["213.239.239.165", "2a01:4f8:0:a112::2:2"],
        "ntp2.inrim.it": ["193.204.114.233", "2001:760:2602::233"],
        "ntp2.jst.mfeed.ad.jp": ["210.173.160.57"],
        "ntp2.net.berkeley.edu": ["169.229.128.142", "2607:f140:ffff:8000:0:8003:0:a"],
        "ntp2.niiftri.irkutsk.ru": ["46.254.241.75"],
        "ntp2.ntp-servers.net": [],
        "ntp2.oma.be": ["193.190.230.37"],
        "ntp2.qix.ca": [],
        "ntp2.stratum1.ru": ["89.109.251.22"],
        "ntp2.stratum2.ru": [],
        "ntp2.time.in.ua": ["31.28.161.71", "2a03:6300:1:100:2::123"],
        "ntp2.vniiftri.ru": ["89.109.251.22"],
        "ntp21.vniiftri.ru": ["89.109.251.25"],
        "ntp3.hetzner.de": ["213.239.239.166", "2a01:4f8:0:a101::2:3"],
        "ntp3.jst.mfeed.ad.jp": ["210.173.160.87"],
        "ntp3.ntp-servers.net": ["95.79.30.113", "85.24.237.71", "176.215.178.239", "178.215.228.24"],
        "ntp3.stratum1.ru": ["89.109.251.23"],
        "ntp3.stratum2.ru": ["2a03:1ac0:5571:3a4a:4aa9:8aff:fee5:aaa0", "2a0f:cdc6:2020::200", "2a0d:8480:0:672::123", "2a03:6f00:a::2f7f"],
        "ntp3.time.in.ua": ["62.149.2.7"],
        "ntp3.vniiftri.ru": ["89.109.251.23"],
        "ntp4.ntp-servers.net": [],
        "ntp4.stratum1.ru": ["89.109.251.24"],
        "ntp4.stratum2.ru": [],
        "ntp4.vniiftri.ru": ["89.109.251.24"],
        "ntp5.ntp-servers.net": [],
        "ntp5.stratum1.ru": ["89.109.251.26"],
        "ntp5.stratum2.ru": [],
        "ntp6.ntp-servers.net": ["2a02:c206:2212:6198::1010", "2a02:2f04:a0e:9199:99::3", "2a02:c6c1:c:207::13", "2001:41d0:304:200::199e"],
        "ntp7.ntp-servers.net": [],
        "ntps1-0.cs.tu-berlin.de": ["130.149.17.21"],
        "ntps1-0.uni-erlangen.de": ["131.188.3.220"],
        "ntps1-1.cs.tu-berlin.de": ["130.149.17.8"],
        "ntps1-1.uni-erlangen.de": ["131.188.3.221"],
        "ntps1.pads.ufrj.br": ["146.164.48.5", "2001:470:1f07:d::5"],
        "pool.ntp.org": ["67.217.246.204", "23.142.248.9", "50.218.103.254", "64.251.10.152"],
        "ptbtime1.ptb.de": ["192.53.103.108", "2001:638:610:be01::108"],
        "ptbtime2.ptb.de": ["192.53.103.104", "2001:638:610:be01::104"],
        "ru.pool.ntp.org": ["45.156.26.126", "195.90.182.235", "31.131.251.6", "5.178.87.94"],
        "rustime01.rus.uni-stuttgart.de": ["129.69.253.1", "2001:7c0:2053:8001::1"],
        "rustime02.rus.uni-stuttgart.de": ["129.69.253.17", "2001:7c0:2053:8002::1"],
        "sth1.ntp.se": ["194.58.202.20", "2a01:3f7:2:1::1"],
        "sth2.ntp.se": ["194.58.202.148", "2a01:3f7:2:2::1"],
        "stratum1.net": ["94.198.132.184"],
        "svl1.ntp.se": ["194.58.205.20", "2a01:3f7:5:1::1"],
        "svl2.ntp.se": ["194.58.205.148", "2a01:3f7:5:2::1"],
        "tempus1.gum.gov.pl": ["194.146.251.100"],
        "tempus2.gum.gov.pl": ["194.146.251.101"],
        "tick.ucla.edu": ["164.67.62.194", "2607:f010:3fe:10:2a0:69ff:fe01:a263"],
        "tick.usask.ca": ["128.233.154.245"],
        "time-a-b.nist.gov": ["132.163.96.1"],
        "time-a-g.nist.gov": ["129.6.15.28"],
        "time-a-wwv.nist.gov": ["132.163.97.1"],
        "time-a.as43289.net": ["178.17.160.12", "2a00:1dc0::12"],
        "time-b-b.nist.gov": ["132.163.96.2"],
        "time-b-g.nist.gov": ["129.6.15.29"],
        "time-b-wwv.nist.gov": ["132.163.97.2"],
        "time-b.as43289.net": ["178.17.161.12", "2a00:1dc0:1::12"],
        "time-c-b.nist.gov": ["132.163.96.3"],
        "time-c-g.nist.gov": ["129.6.15.30"],
        "time-c-wwv.nist.gov": ["132.163.97.3"],
        "time-c.as43289.net": ["178.17.162.12", "2a00:1dc0:2::12"],
        "time-d-b.nist.gov": ["132.163.96.4", "2610:20:6f96:96::4"],
        "time-d-g.nist.gov": ["129.6.15.27", "2610:20:6f15:15::27"],
        "time-d-wwv.nist.gov": ["132.163.97.4", "2610:20:6f97:97::4"],
        "time-e-b.nist.gov": ["132.163.96.6", "2610:20:6f96:96::6"],
        "time-e-g.nist.gov": ["129.6.15.26", "2610:20:6f15:15::26"],
        "time-e-wwv.nist.gov": ["132.163.97.6", "2610:20:6f97:97::6"],
        "time.apple.com": ["17.253.20.253", "17.253.2.125", "17.253.20.125", "2620:149:a16:3000::31", "2620:149:a33:3000::1e2", "2620:149:a33:3000::1f2"],
        "time.cloudflare.com": ["162.159.200.123", "162.159.200.1", "2606:4700:f1::1", "2606:4700:f1::123"],
        "time.esa.int": ["192.171.1.150"],
        "time.euro.apple.com": ["17.253.2.253", "17.253.20.125", "17.253.20.253", "2620:149:a33:3000::1f2", "2620:149:a33:4000::1e2", "2620:149:a16:4000::31"],
        "time.facebook.com": ["129.134.29.123", "2a03:2880:ff0b::123"],
        "time.fu-berlin.de": ["130.133.1.10"],
        "time.google.com": ["216.239.35.12", "216.239.35.8", "216.239.35.0", "216.239.35.4", "2001:4860:4806::", "2001:4860:4806:4::", "2001:4860:4806:8::", "2001:4860:4806:c::"],
        "time.nist.gov": ["132.163.96.6"],
        "time.nrc.ca": ["132.246.11.238", "132.246.11.237", "132.246.11.227", "132.246.11.229"],
        "time.ufe.cz": ["147.231.2.6"],
        "time.windows.com": ["168.61.215.74"],
        "time1.esa.int": ["192.171.1.150"],
        "time1.facebook.com": ["129.134.28.123", "2a03:2880:ff0b::123"],
        "time1.google.com": ["216.239.35.0", "2001:4860:4806::"],
        "time1.stupi.se": ["192.36.143.150"],
        "time2.facebook.com": ["129.134.29.123", "2a03:2880:ff0c::123"],
        "time2.google.com": ["216.239.35.4", "2001:4860:4806:4::"],
        "time3.facebook.com": ["129.134.25.123", "2a03:2880:ff08::123"],
        "time3.google.com": ["216.239.35.8", "2001:4860:4806:8::"],
        "time4.facebook.com": ["2a03:2880:ff09::123"],
        "time4.google.com": ["2001:4860:4806:c::"],
        "time5.facebook.com": ["129.134.27.123", "2a03:2880:ff0a::123"],
        "timekeeper.isi.edu": ["128.9.176.30"],
        "tock.usask.ca": ["128.233.150.93"],
        "tock.usshc.com": ["199.102.46.72"],
        "ts1.aco.net": ["193.171.23.163", "2001:628:2030:dcf1::ac0"],
        "ts2.aco.net": ["131.130.251.107", "2001:62a:4:311::ac0"],
        "utcnist.colorado.edu": ["128.138.140.44"],
        "utcnist2.colorado.edu": ["128.138.141.172"],
        "vniiftri.khv.ru": ["212.19.6.218"],
        "vniiftri2.khv.ru": ["212.19.17.26"],
        "x.ns.gin.ntt.net": ["129.250.35.250", "2001:418:3ff::53"],
        "y.ns.gin.ntt.net": ["129.250.35.251", "2001:418:3ff::1:53"],
        "zeit.fu-berlin.de": ["160.45.10.8"],
    },
}

NTPIPS = MakeIPDict(NTPSERVERS)
