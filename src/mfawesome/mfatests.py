#!/usr/bin/env python3
from __future__ import annotations

import ast
import functools
import json
import logging
import os
import shutil
import sys
import traceback
import unittest
from contextlib import suppress
from pathlib import Path

import rich

__filepath = Path(__file__)
sys.path.insert(0, __filepath.parents[0] / "src")
import mfawesome
from mfawesome import config
from mfawesome.config import EXAMPLE_CONFIG, ConfigIO, ShowMFAConfigVars
from mfawesome.exception import DependencyMissingError, MFAwesomeError, TestComplete, TestFailError
from mfawesome.logutils import SetLoggingLevel, SetupLogging

with suppress(ImportError, ModuleNotFoundError, DependencyMissingError):
    from mfawesome.qrcodes import AuthSecret, ConvertAuthSecretsToDict, ExportToGoogleAuthenticator, ParseQRUrl, ScanQRDir, ScanQRImage

from mfawesome.mfa_secrets import GenerateSecret
from mfawesome.utils import CheckQRImportSupport, FastInternetCheck, PathEx, colors, print_with_sep_line, printcrit, printerr, printok

mfarun = mfawesome.exec_mfawesome.run

TESTLOGLEVEL = "DEBUG"
mfarun = functools.partial(mfarun, test=True, now=True, noclearscreen=True, showsecrets=False, noendtimer=True, loglevel=TESTLOGLEVEL)
# mfarun = functools.partial(mfarun, args={"test": True, "now": True, "noclearscreen": True, "showsecrets": False, "noendtimer": True, "loglevel": TESTLOGLEVEL})
logger = logging.getLogger("mfa")
logger = SetupLogging(level=TESTLOGLEVEL)


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
    # return config.CheckSecretsEncrypted(config.LoadConfig()[1]["secrets"])
    return config.CheckSecretsEncrypted(config.Readyaml(configfile)["secrets"])


class TestName:
    _count = 1
    FAILEDTESTS = []
    TESTSPASSED = True

    def __init__(self, testname: str):
        self.count = TestName._count
        self.name = testname
        self.msg = f"#{self.count} - {testname}"
        print_test_msg(self.msg, pdelim=True)
        TestName._count += 1

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def failed(self, fmsg: str = "") -> None:
        if fmsg:
            fmsg = f": {fmsg}"
        outstr = f"FAILED: {self.msg} {fmsg}"
        printerr(outstr)
        TestName.FAILEDTESTS.append(outstr)
        TestName.TESTSPASSED = False
        print_test_msg()

    def passed(self, pmsg: str = "") -> None:
        if pmsg:
            pmsg = f": {pmsg}"
        printok(f"PASSED: {self.msg} {pmsg}")
        print_test_msg()


def main() -> None:
    try:
        print_test_msg("Preparing test environment")
        # os.environ["NTP_SERVERS"] = "pfsense.milloy.arpa:time.google.com"
        os.environ["MFAWESOME_CONFIG"] = "/tmp/mfa/mfa_test.conf"
        os.environ["MFAWESOME_PASSWD"] = "mfaX"  # noqa: S105
        os.environ["MFAWESOME_LOGLEVEL"] = "DEBUG"
        os.environ["MFAWESOME_TEST"] = "1"
        ShowMFAConfigVars()
        MFACONF = Path(os.environ.get("MFAWESOME_CONFIG", None))

        if Path(os.environ.get("MFAWESOME_CONFIG")).exists():
            print_test_msg(f"Deleting existing test config file at {os.environ.get('MFAWESOME_CONFIG')}")
            Path(os.environ.get("MFAWESOME_CONFIG")).unlink()

        if MFACONF is None:
            raise RuntimeError("Environment variables for MFAwesome must be set for testing")
        #########################################################################
        TESTNAME = TestName("checkqrsupport")
        print_test_msg(f"{TESTNAME}: Check for all dependencies required for QR importing (exporting should be supported)")
        with suppress(TestComplete):
            result, err = CheckQRImportSupport()

        if not result:
            TESTNAME.failed(f"QR Export not supported: {err!r}")
        else:
            TESTNAME.passed()

        #########################################################################
        TESTNAME = TestName("checkinternet")
        print_test_msg(f"{TESTNAME}: Check for working internet connection")
        with suppress(TestComplete):
            result = FastInternetCheck()

        if not result:
            TESTNAME.failed("Unable to connect to internet")
        else:
            TESTNAME.passed()
        #########################################################################

        TESTNAME = TestName("generateconfig")
        with suppress(TestComplete):
            mfarun(generateconfig=str(MFACONF))
        # logger.debug(f"Generated config: {MFACONF.read_text()=}")
        print_test_msg(f"{TESTNAME}: Config encrypted?: {are_secrets_encrypted(MFACONF)}")
        if not MFACONF.exists():
            TESTNAME.failed("The config file was not created successfully!")
        else:
            TESTNAME.passed()
        #########################################################################

        TESTNAME = TestName("encryptconfig")
        with suppress(TestComplete):
            mfarun(encryptconfig=True)
        print_test_msg(f"{TESTNAME.msg}: Config encrypted?: {are_secrets_encrypted(MFACONF)}")
        # logger.debug(f"Encrypted config: {MFACONF.read_text()=}")
        if not are_secrets_encrypted(MFACONF):
            TESTNAME.failed("Secrets are NOT encrypted!")
        TESTNAME.passed()

        #########################################################################

        TESTNAME = TestName("exportconfig")
        exportfile = Path("/tmp/mfa_export.test")
        if exportfile.exists():
            exportfile.unlink()
        print_test_msg(f"Testing export config to {exportfile!s}")
        with suppress(TestComplete):
            mfarun(exportconfig=str(exportfile))
        print_test_msg(f"{TESTNAME.msg}: Config encrypted?: {are_secrets_encrypted(MFACONF)}")
        if not are_secrets_encrypted(exportfile):
            TESTNAME.failed("Secrets are NOT encrypted!")
        else:
            TESTNAME.passed()
        exportfile.unlink()

        #########################################################################

        TESTNAME = TestName("changepassword")
        with suppress(TestComplete):
            mfarun(changepassword=True)
        print_test_msg(f"{TESTNAME.msg}: Config encrypted?: {are_secrets_encrypted(MFACONF)}")
        if not are_secrets_encrypted(MFACONF):
            TESTNAME.failed("Secrets are NOT encrypted!")
        else:
            TESTNAME.passed()

        #########################################################################

        TESTNAME = TestName("generatesecret")
        try:
            with suppress(TestComplete):
                mfarun(generatesecret=True)
        except MFAwesomeError as e:
            TESTNAME.failed(f"Test failed with exception {e!r}")
        else:
            TESTNAME.passed()

        #########################################################################
        TESTNAME = TestName("searchsecrets")
        searchterm = "madeupwebsite"
        print_test_msg(f"Searching secrets for term {searchterm}...")
        try:
            with suppress(TestComplete):
                mfarun(searchsecrets=searchterm)
        except MFAwesomeError as e:
            TESTNAME.failed(f"Test failed with exception {e!r}")
        else:
            TESTNAME.passed()

        #########################################################################
        TESTNAME = TestName("printconfig")
        print_test_msg(f"Printing config")
        try:
            with suppress(TestComplete):
                mfarun(printconfig=True)
        except MFAwesomeError as e:
            TESTNAME.failed(f"Test failed with exception {e!r}")
        else:
            TESTNAME.passed()

        #########################################################################

        TESTNAME = TestName("removesecret")
        secretname = "Example Secret"
        with suppress(TestComplete):
            mfarun(removesecret=secretname)
        with ConfigIO() as cfgio:
            if secretname not in cfgio.config["secrets"]:
                TESTNAME.passed(f"Success: Removed secret!  {secretname}")
            else:
                TESTNAME.failed("Failed to remove secret!")

        #########################################################################
        # hotp
        TESTNAME = TestName("hotp")
        secretname = "example_hotp_secret"
        try:
            with suppress(TestComplete):
                mfarun(filterterm=secretname, hotp=True)
        except MFAwesomeError as e:
            TESTNAME.failed("Failed to generate HOTP!")
        else:
            TESTNAME.passed(f"Success: HOTP!  {secretname}")

        #########################################################################
        # EXPORT QR SECRETS
        testsecrets = EXAMPLE_CONFIG["secrets"]
        imagedir = PathEx("/tmp/testsecrets")
        TESTNAME = TestName("Export Secrets QR images to Google Authenticator")
        images = ExportToGoogleAuthenticator(testsecrets, imagedir)
        logger.critical(f"{images=}")
        exportok = False
        if len(images) > 0:
            exportok = True
            TESTNAME.passed()
        else:
            TESTNAME.failed(f"No QR's could be successfully exported")
            # raise RuntimeError("test fail")
        import time

        time.sleep(30)

        #########################################################################
        # IMPORT QR SECRETS
        TESTNAME = TestName("Export Secrets Tp Google Authenticator QR Images")
        if not exportok:
            TESTNAME.failed("Failed to export images, cannot run test")
        else:
            qrsupport, err = CheckQRImportSupport()
            if qrsupport:
                testsecrets2 = ConvertAuthSecretsToDict(ParseQRUrl(ScanQRImage(images[0])[0]))
                if testsecrets2.keys() != testsecrets.keys():
                    TESTNAME.failed(f"Secrets do not match: {list(testsecrets.keys())} != {list(testsecrets2.keys())}")
                else:
                    TESTNAME.passed()
            else:
                TESTNAME.failed(f"QR Export dependencies not installed: {err!r}")
        if imagedir.is_dir():
            shutil.rmtree(imagedir)

        #########################################################################
        TESTNAME = TestName("addsecrets")
        testaddsecrets = {
            "secretname": {"totp": GenerateSecret(), "user": "mfawesome_user", "url": "www.example.com"},
            "anothersecret": {"totp": GenerateSecret(), "user": "another_mfa_user", "url": "www.example2.com"},
        }
        with suppress(TestComplete):
            mfarun(addsecrets=json.dumps(testaddsecrets))

        with ConfigIO() as cfgio:
            if all(x in cfgio.config["secrets"] for x in testaddsecrets):
                TESTNAME.passed(f"Success: Added secrets!  {list(cfgio.config['secrets'].keys())}")
            else:
                TESTNAME.failed("Failed to add secrets!")

        #########################################################################
        TESTNAME = TestName("Run Normally")
        try:
            with suppress(TestComplete):
                mfarun()
                mfarun(hotp=True)
        except MFAwesomeError as e:
            TESTNAME.failed(f"Test failed with exception {e!r}")
        else:
            TESTNAME.passed()

        #########################################################################
        # continuous
        # TESTNAME = TestName("Run Continuous")
        # try:
        #     with suppress(TestComplete):
        #         mfarun(continuous=True, showsecrets=True, noendtimer=True)  # , now=True, noclearscreen=True, timelimit=3)
        # except MFAwesomeError as e:
        #     TESTNAME.failed(f"Test failed with exception {e!r}")
        # else:
        #     TESTNAME.passed()

        #########################################################################

        TESTNAME = TestName("decryptconfig")
        with suppress(TestComplete):
            mfarun(decryptconfig=True)
        print_test_msg(f"{TESTNAME}: Config encrypted?: {are_secrets_encrypted(MFACONF)}")
        logger.debug(f"Decrypted config: {MFACONF.read_text()[0:100]=}...")
        if are_secrets_encrypted(MFACONF):
            TESTNAME.failed("Secrets are NOT decrypted!")
        else:
            TESTNAME.passed()

        #########################################################################

    except Exception as e:
        TestName.TESTSPASSED = False
        printcrit(f"Exception during testing - testing can NOT continue: {e!r}")
        traceback.print_exception(e)
        raise e
    finally:
        print_test_msg("Deleting test config...", pdelim=False)
        if Path(os.environ["MFAWESOME_CONFIG"]).exists():
            Path(Path(os.environ["MFAWESOME_CONFIG"])).unlink()
        with suppress(Exception):
            if exportfile.exists():
                exportfile.unlink()
        if TestName.TESTSPASSED:
            printcrit("THIS IS WRONG")
            printok("TESTS COMPLETE - ALL TESTS PASSED!")
        else:
            print_with_sep_line(printerr, f"\n{len(TestName.FAILEDTESTS)} TESTS FAILED!", "max_red")

            for ft in TestName.FAILEDTESTS:
                printerr(f"Test Failed: {ft}")


if __name__ == "__main__":
    main()
