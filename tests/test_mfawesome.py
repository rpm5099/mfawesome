from __future__ import annotations

import ast
import copy
import functools
import json
import logging
import os
import shutil
import sys
import time
import traceback
import unittest
from contextlib import suppress
from pathlib import Path

import pytest
import rich

__filepath = Path(__file__)
sys.path.insert(0, __filepath.parents[0] / "src")
import mfawesome
from mfawesome import config
from mfawesome.config import EXAMPLE_CONFIG, ReadConfigFile, ShowMFAConfigVars
from mfawesome.exception import EXCEPTIONTESTMODE, DependencyMissingError, xTestComplete
from mfawesome.logutils import SetupLogging

with suppress(ImportError, ModuleNotFoundError, DependencyMissingError):
    from mfawesome.qrcodes import AuthSecret, ConvertAuthSecretsToDict, ParseQRUrl, QRExport, ScanQRDir, ScanQRImage

from mfawesome.utils import FastInternetCheck, PathEx, colors

# ruff: noqa: S101

mfarun = mfawesome.exec_mfawesome.main

"""
Manually set environment at cli
export MFAWESOME_CONFIG=/tmp/mfa/mfa_test.conf
export MFAWESOME_PWD="mfaX"
export MFAWESOME_LOGLEVEL=30
export MFAWESOME_TEST=1
mfa config generate /tmp/mfa/mfa_test.conf
"""

TESTLOGLEVEL = "DEBUG"
MFACONF = None
TESTDATADIR = PathEx("/tmp/mfa")
ReadConfigFile = functools.partial(ReadConfigFile, testmode=True)
logger = logging.getLogger("mfa")
logger = SetupLogging(level=TESTLOGLEVEL)


def rmtree(f: Path, missing_ok: bool = False):
    if f.is_file():
        f.unlink()
    elif f.is_dir():
        for child in f.iterdir():
            rmtree(child)
        f.rmdir()
    else:
        if missing_ok:
            return
        raise OSError(f"Directory does not exist: {f!s}")


def print_test_msg(msg: str | None = None, pdelim: bool = False) -> None:
    delim = colors("PURPLE", "=" * 80)
    if pdelim:
        print(delim)
    if msg is not None:
        print(colors("PURPLE", "*" * 20 + "TEST MODE MESSAGE: " + str(msg)))
        if pdelim:
            print(delim)
        return
    if pdelim:
        print("\n\n\n\n")


def dumpconfig() -> None:
    rich.print_json(json.dumps(config.ReadConfigFile()))


def are_secrets_encrypted(configfile: str | Path) -> bool:
    return config.CheckSecretsEncrypted(config.Readyaml(configfile)["secrets"])


def CurrentTestSecrets():
    logger.debug(f'Current test secrets: {set(ReadConfigFile(MFACONF)["secrets"].keys())}', stacklevel=2)


def SetupTestMode():
    if TESTDATADIR.exists():
        shutil.rmtree(TESTDATADIR)
    print_test_msg("Preparing test environment")
    # os.environ["NTP_SERVERS"] = "pfsense.milloy.arpa:time.google.com"
    os.environ["MFAWESOME_CONFIG"] = "/tmp/mfa/mfa_test.conf"
    os.environ["MFAWESOME_PWD"] = "mfaX"  # noqa: S105
    os.environ["MFAWESOME_LOGLEVEL"] = "DEBUG"
    os.environ["MFAWESOME_TEST"] = "1"
    ShowMFAConfigVars()
    global MFACONF
    MFACONF = Path(os.environ.get("MFAWESOME_CONFIG", None))

    if Path(os.environ.get("MFAWESOME_CONFIG")).exists():
        print_test_msg(f"Deleting existing test config file at {os.environ.get('MFAWESOME_CONFIG')}")
        Path(os.environ.get("MFAWESOME_CONFIG")).unlink()

    if MFACONF is None:
        raise RuntimeError("Environment variables for MFAwesome must be set for testing")


def test_checkinternet():
    assert FastInternetCheck()


def test_generateconfig():
    SetupTestMode()
    exc = None
    runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
    try:
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = exc is None
    assert result


def test_encryptconfig():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config encrypt"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = are_secrets_encrypted(MFACONF) and exc is None
    assert result


def test_decryptconfig():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config encrypt"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config decrypt"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = not are_secrets_encrypted(MFACONF) and exc is None
    assert result


def test_exportconfig():
    SetupTestMode()
    exc = None
    exportfile = Path("/tmp/mfa_export.test")
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config encrypt"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config export {exportfile}"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = are_secrets_encrypted(exportfile) and exc is None
    if exportfile.exists():
        exportfile.unlink()
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    assert result


def test_changepassword():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config encrypt"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config password"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = are_secrets_encrypted(MFACONF) and exc is None
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    assert result


def test_generatesecret():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} secrets generate"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = exc is None
    assert result


def test_searchsecrets():
    SetupTestMode()
    searchterm = "madeupwebsite"
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets search {searchterm}"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    result = exc is None
    assert result


def test_printconfig():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} config print"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    result = exc is None
    assert result


def test_addsecret():
    SetupTestMode()
    newsecret = '{"AddedSecret": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}'
    secretname = next(iter(json.loads(newsecret).keys()))
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets add".split()
        runargs.append(newsecret)
        mfarun(runargs)
    except Exception as e:
        exc = e
    result = secretname in ReadConfigFile(MFACONF)["secrets"]  # set(cfgc["secrets"].keys())
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    assert result


def test_removesecret():
    SetupTestMode()
    secretname = "Example Secret"
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets remove".split()
        runargs.append(secretname)
        mfarun(runargs)
    except Exception as e:
        exc = e
    cfgc = copy.deepcopy(EXAMPLE_CONFIG)
    cfgc["secrets"].pop(secretname)
    result = set(cfgc["secrets"].keys()) == set(ReadConfigFile(MFACONF)["secrets"].keys())
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    assert result


def test_hotp():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} hotp".split()
        mfarun(runargs)
    except Exception as e:
        exc = e
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    result = exc is None
    assert result


def test_qrexport():
    SetupTestMode()
    imagedir = PathEx("/tmp/testsecrets")
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets export {imagedir}"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    if MFACONF.exists():
        MFACONF.unlink()
    if imagedir.is_dir():
        shutil.rmtree(imagedir)
    result = exc is None
    assert result


def test_qrimport():
    SetupTestMode()
    imagedir = PathEx("/tmp/testsecrets")
    newsecret = '{"QRImportAddedSecret": {"totp":"FSSQPOR4HVN6Y5JGJTA43GCBJZWCHQ7GI23LLLP4QMBF2HJT23EQ", "user":"theduke", "url":"www.example.com"}}'
    secretname = next(iter(json.loads(newsecret).keys()))
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets add".split()
        runargs.append(newsecret)
        mfarun(runargs)
        runargs = f"-T -L {TESTLOGLEVEL} secrets export {imagedir}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} secrets remove".split()
        runargs.append(secretname)
        mfarun(runargs)
        runargs = f"-T -L {TESTLOGLEVEL} secrets import {imagedir}"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    result = secretname in ReadConfigFile(MFACONF)["secrets"] and exc is None
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    if imagedir.is_dir():
        shutil.rmtree(imagedir)

    assert result


def test_runnormal():
    SetupTestMode()
    exc = None
    try:
        runargs = f"-T -L {TESTLOGLEVEL} config generate {MFACONF}"
        mfarun(runargs.split())
        runargs = f"-T -L {TESTLOGLEVEL} run -nN"
        mfarun(runargs.split())
    except Exception as e:
        exc = e
    if MFACONF.parent.exists():
        shutil.rmtree(MFACONF.parent)
    result = exc is None
    assert result
