from __future__ import annotations

import copy
import logging
import os
import sys

from mfawesome.utils import PrintStack, colors, flatten, printcrit, printdbg

LOGGERNAME = "mfa"


class StdoutFormatter(logging.Formatter):
    def __init__(self, nocolors: bool = False, details: bool = True) -> None:
        detailedfmt = "%(name)s-%(levelname)s %(asctime)s (%(module)s.%(funcName)s.%(lineno)d): %(message)s"
        shortfmt = "%(name)s-%(levelname)s: %(message)s"
        fmt = detailedfmt if details else shortfmt
        COLOREDFORMATS = {
            logging.DEBUG: colors("debug_blue", fmt),
            logging.INFO: colors("grey", fmt),
            logging.WARNING: colors("yellow", fmt),
            logging.ERROR: colors("bold_red", fmt),
            logging.CRITICAL: colors("white_on_red", fmt),
        }

        NCFORMATS = {
            logging.DEBUG: fmt,
            logging.INFO: fmt,
            logging.WARNING: fmt,
            logging.ERROR: fmt,
            logging.CRITICAL: fmt,
        }
        if nocolors:
            self.FORMATS = NCFORMATS
        else:
            self.FORMATS = COLOREDFORMATS

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %I:%M:%S%p")
        return formatter.format(record)


def NormalizeLogLevel(level: int | str | None, defaultlevel: str | int | None = "INFO") -> str:
    """Return the str value of the level regardless of the input"""
    levelcopy = copy.copy(level)
    if level == "dbg":
        level = "DEBUG"
    if level is None or level == "":
        level = defaultlevel
    elif level in (-1, "-1"):
        level = "NOTSET"
    elif isinstance(level, int) or (isinstance(level, str) and ((level.startswith("-") and level[1:].isdigit()) or level.isdigit())):
        level = int(level)
        level = "NOTSET" if level <= 0 else logging._levelToName.get(level, "INVALID")
    elif isinstance(level, str):
        level = level.upper()
        level = logging._nameToLevel.get(level.upper(), "INVALID")
    else:
        level = "INVALID"

    if level == "INVALID":
        printdbg(f"Logging disabled or input value was invalid: {levelcopy}. Returning default level {defaultlevel}")
        level = defaultlevel
    return level


def SetupLogging(level: int | str | None = None, nocolors: bool = False, details: bool = True) -> None:
    if NormalizeLogLevel(level=level, defaultlevel=None) is None and "MFAWESOME_LOGLEVEL" in os.environ:
        level = NormalizeLogLevel(os.environ.get("MFAWESOME_LOGLEVEL"), defaultlevel="INFO")
    level = NormalizeLogLevel(level)
    logger = logging.getLogger(LOGGERNAME)
    for handler in logger.handlers:
        logger.removeHandler(handler)
    logger.setLevel(level)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(StdoutFormatter(nocolors=nocolors, details=details))
    logger.addHandler(stdout_handler)
    # logger.debug(f"Logging to stdout level '{logging.getLevelName(logger.level)}' named '{logger.name}' enabled")
    return logger


def SetLoggingLevel(level: int | str | None) -> None:
    if NormalizeLogLevel(level=level, defaultlevel=None) is None and "MFAWESOME_LOGLEVEL" in os.environ:
        level = NormalizeLogLevel(os.environ.get("MFAWESOME_LOGLEVEL"), defaultlevel="INFO")
    level = NormalizeLogLevel(level)
    logger = logging.getLogger(LOGGERNAME)
    for handler in logger.handlers:
        handler.setLevel(level)
    logger.setLevel(level)
    logger.debug(f"Log level set to : {level}")


def DebugLogging() -> None:
    logger = logging.getLogger(LOGGERNAME)
    rootlogger = logging.getLogger()
    # dir(rootlogger)
    print("rootlogger: ", rootlogger.level, f"{LOGGERNAME} logger:", logger.level)
    print("root handlers: ", logging.getLogger().handlers)
    print(f"{LOGGERNAME} handlers: ", logging.getLogger(LOGGERNAME).handlers)
    logger.debug("debug test")
    logger.info("info test")
    logger.warning("warning test")
    logger.error("error test")
    logger.critical("critical test")
