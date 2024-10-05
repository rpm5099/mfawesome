#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import traceback
from contextlib import suppress
from pathlib import Path
from pprint import pformat, pprint
from typing import TYPE_CHECKING

import rich

import mfawesome
from mfawesome import (
    __author__,
    __author_email__,
    __build_date__,
    __description__,
    __logo__,
    __title__,
    __url__,
    __version__,
    config,
    exception,
    logutils,
    mfa_secrets,
    ntptime,
    qrcodes,
    totp,
)
from mfawesome.config import ConfigDebug, ConfigIO, GenerateDefaultConfig, LoadNTPServers, LoadQRSecrets, LocateConfig, PrintConfig, TestCheck
from mfawesome.exception import KILLED, ArgumentError, ConfigError, ConfigNotFoundError, DependencyMissingError, MFAwesomeError, ScreenResizeError, ScreenSafe, StopIPython, TestFailError
from mfawesome.logutils import NormalizeLogLevel, SetLoggingLevel, SetupLogging
from mfawesome.mfa_secrets import GenerateSecret
from mfawesome.qrcodes import ExportToGoogleAuthenticator
from mfawesome.totp import multitotp, multitotp_continuous, runhotp
from mfawesome.utils import (
    SHOW_CURSOR,
    ANSIColors,
    CheckFile,
    CheckQRImportSupport,
    ErrorExitCleanup,
    IsIPython,
    PathEx,
    PrintList,
    PrintStack,
    SearchSecrets,
    check_yes_no,
    colors,
    flatten,
    jsondump,
    print_with_sep_line,
    printcrit,
    printdbg,
    printerr,
    printnorm,
    printok,
    printwarn,
    sjoin,
)

with suppress(ImportError, ModuleNotFoundError, exception.DependencyMissingError):
    from mfawesome.qrcodes import ImportFromGoogleAuthenticator

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("mfa")

CFGFILE = None


def MFAExit(code: int = 0) -> None:
    test = config.TestCheck()
    if test and code == 0:
        printdbg("Ignoring exit in test mode")
        return code
    if test and code != 0:
        raise exception.TestFailError(f"Non-zero exit code - Test failure!")
    if IsIPython():
        raise exception.StopIPython("Stop right there!")
    sys.exit(code)


def main():
    parser = argparse.ArgumentParser(
        prog="MFAwesome",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{mfawesome.__logor__}\nMFAwesome Multifactor Authentication CLI tool.  Protect your secrets and access them easily. Run 'mfa'",
    )

    parser.add_argument("filterterm", action="store", nargs="?", default=None, type=str, help="Term used to filter secrets")
    # ALWAYS USED
    parser.add_argument("--configfile", type=pathlib.Path, default=None, help="Specify config file with your secrets")  # default=pathlib.Path().cwd(),
    # parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase loging output above what is set in config file (or default) one level for each v")
    parser.add_argument("-L", "--loglevel", default=None, help="Alternative to '-v', indicate specific loglevel")
    parser.add_argument("-T", "--test", action="store_true", help="Run in test mode - FOR DEBUGGING ONLY")

    # RUN AND EXIT
    group = parser.add_argument_group()
    doexit_group = group.add_mutually_exclusive_group(required=False)
    doexit_group.add_argument("--encryptconfig", "--encryptsecrets", action="store_true", help="Encrypt secrets in config file (if not already encrypted)")
    doexit_group.add_argument("--decryptconfig", "--decryptsecrets", action="store_true", help="Permanently decrypt secrets in config file (if encrypted)")
    doexit_group.add_argument(
        "--exportconfig",
        type=pathlib.Path,
        # default=PathEx("mfa_exported_config.conf").resolve(),
        nargs="?",
        const=PathEx("mfa_exported_config.conf").resolve(),
        help="Export config to the specified file (required).  Keylog protection will be enabled.  Please see the documentation for details",
    )
    doexit_group.add_argument("-C", "--changepassword", action="store_true", help="Change password for secrets - unencrypted secrets are never written to disk")
    doexit_group.add_argument(
        "--generateconfig",
        nargs="?",
        # type=PathEx,
        const=Path.home() / ".config/mfawesome/mfawesome.conf",
        help="Generate a new config file in the default location '$HOME/.config/mfawesome/mfawesome.conf' or argument to --generateconfig=/some/config/file - add your secrets there",
    )
    doexit_group.add_argument("-P", "--printconfig", action="store_true", help="Print config and exit")
    doexit_group.add_argument("-z", "--searchsecrets", type=str, help="Search through all secrets for a filtertem and display matching.  '--exact' flag is applicable")
    doexit_group.add_argument(
        "-A",
        "--addsecrets",
        # type=dict,
        help='Add new secret(s), must be in format of {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}.  Multiple secrets are acceptable',
    )
    doexit_group.add_argument(
        "-Q",
        "--addqrsecrets",
        type=pathlib.Path,
        # default=pathlib.Path().cwd(),
        nargs=1,
        help="Add secrets from QR images by specifying directory containing the images.  Requires libzbar - https://github.com/mchehab/zbar",
    )
    doexit_group.add_argument("-S", "--generatesecret", action="store_true", help="Generate and print an OTP secret key and exit")
    doexit_group.add_argument("-D", "--configdebug", action="store_true", help="Show config file resolution details")
    doexit_group.add_argument(
        "-G",
        "--googleauthexport",
        type=pathlib.Path,
        # default=Path().cwd(),
        help="Export codes in QR images to be scanned by Google Authenticator.  Set export dir via '--googleauthexport=/some/path/here' - default is current directory",
    )
    doexit_group.add_argument("--runtests", action="store_true", help="Run tests")
    doexit_group.add_argument("-V", "--version", action="store_true", help="Show version information")
    doexit_group.add_argument("--removesecret", action="store", type=str, help="Remove a secret by specifying the secret name")

    # USED ONLY FOR DEFAULT BEHAVIOR - DSPLAYING CODES
    # Check if any are specified when not in "normal" mode and display warning
    parser.add_argument("-c", "--continuous", action="store_true", help="Enable continuous code display - default to 90 but add optional argument for otherwise")
    parser.add_argument("-e", "--exact", action="store_true", help="Disable fuzzy matching on secret filterterm")
    parser.add_argument("-s", "--showsecrets", action="store_true", help="Enable showing secrets - WARNING: this will reveal sensitive information on your screen")
    parser.add_argument("-l", "--noclearscreen", action="store_true", help="Disable clearing the screen before exit - WARNING - can leave sensitive data on the screen")
    parser.add_argument("-n", "--now", action="store_true", help="Get codes now even if they expire very soon.  N/A for continuous.")
    parser.add_argument("-E", "--showerr", action="store_true", help="Show errors getting and parsing codes")
    parser.add_argument("-m", "--timelimit", type=float, help="Length of time to show codes continuously (Default 90.0 seconds)")  # default=90.0,
    parser.add_argument("-t", "--noendtimer", action="store_true", help="Disable countdown timer for codes, N/A for --continuous")
    parser.add_argument("-H", "--hotp", action="store_true", help="Calculate HOTP codes, using a filterterm if supplied.  Counters will be incremented in the config")

    args = parser.parse_args()
    global logger
    logger = logutils.SetupLogging(level=args.loglevel)
    run(**vars(args))


def ValidateArguments(args):
    for k, v in args.items():
        if not k.startswith("_"):
            logger.debug(f"{k}: {v}")
    doexit = {
        "encryptconfig",
        "decryptconfig",
        "exportconfig",
        "changepassword",
        "generateconfig",
        "printconfig",
        "searchsecrets",
        "addsecrets",
        "generatesecret",
        "configdebug",
        "googleauthexport",
        "runtests",
        "version",
    }

    requiresconfigio = {"encryptconfig", "decryptconfig", "exportconfig", "changepassword", "printconfig", "searchsecrets", "addsecrets", "googleauthexport"}
    noconfigio = {"generatesecret", "configdebug", "runtests", "version", "generateconfig"}
    onlynormal = {"continuous", "exact", "showsecrets", "noclearscreen", "now", "showerr", "timelimit", "noendtimer", "hotp"}
    nofilterterm = {"configdebug", "version", "encryptconfig", "decryptconfig", "exportconfig", "changepassword", "generateconfig", "addsecrets", "addqrsecrets", "generatesecret"}
    allowedfilterterm = {"searchsecrets"}
    # allopts = sjoin(requiresconfigio, noconfigio, onlynormal, doexit, nofilterterm, allowedfilterterm, allopts

    def AllBut(buts, allset):  # =set().union([doexit, requiresconfigio, noconfigio, onlynormal])):
        for x in buts:
            allset = allset.remove(x)
        return allset

    def FindEnabled(someiter):
        for x in someiter:
            if args.get(x):
                return x
        return None
        # raise ValueError(f"Nothing enabled; {someiter}")

    def FindAllEnabled(someiter):
        r = set()
        for x in someiter:
            if args.get(x):
                r.add(x)
        return r

    # add all the checks here
    if args.get("test") is True:
        os.environ["MFAWESOME_TEST"] = "1"

    if args.get("filterterm") and (enabled := FindEnabled(nofilterterm)):
        raise ArgumentError(f"{enabled}() does not accept a filterterm: {args.get('filterterm')})")

    if FindEnabled(doexit) and (enb := FindAllEnabled(onlynormal)):
        logger.warning(f"These options are being ignored: {enb}")

    if not args.get("configdebug") and args.get("configfile") is not None and not CheckFile(args.get("configfile")):
        args["configfile"] = PathEx(args["configfile"])
        raise ArgumentError(f"This config file does not exist: '{args.get('configfile')!s}' ")

    if args.get("addqrsecrets"):
        qrsupport, err = CheckQRImportSupport()
        if qrsupport is False:
            printerr(
                f"Required dependencies are missing for QR image support.  Try installing with 'pip install mfawesome[all]' or see the README.  The Zbar libary is required and must be installed externally - see https://github.com/mchehab/zbar: {err!r}",
            )
            sys.exit(1)


def _RunNormal(
    configio: ConfigIO,
    filterterm: str | None = None,
    continuous: bool = False,
    exact: bool = False,
    showsecrets: bool = True,
    noclearscreen: bool = False,
    now: bool = False,
    showerr: bool = False,
    timelimit: float | None = None,
    noendtimer: bool = False,
) -> None:
    if configio.secretscount == 0:
        raise MFAwesomeError(f"The config file {configio.configfile!s} contains no secrets")
    if timelimit is None:
        timelimit = 90.0
    if showsecrets:
        printwarn("WARNING: Enabled showing secrets - this will reveal sensitive information on your screen!")
    secrets = configio.config["secrets"]
    try:
        timeserver = configio.config.get("timeserver", None)
        timeserver = timeserver if timeserver else ntptime.LoadNTPServers()
        if continuous:
            totp.multitotp_continuous(
                secrets,
                timelimit=timelimit,
                showsecrets=showsecrets,
                showerr=showerr,
                filterterm=filterterm,
                clearscreen=not noclearscreen,
                exact=exact,
                timeservers=timeserver,
            )
        else:
            totp.multitotp(
                secrets=secrets,
                now=now,
                showsecrets=showsecrets,
                showerr=showerr,
                endtimer=not noendtimer,
                filterterm=filterterm,
                clearscreen=not noclearscreen,
                exact=exact,
                timeservers=timeserver,
            )
    except exception.ScreenResizeError as e:
        exception.ScreenSafe()
    except KeyboardInterrupt as e:
        raise exception.KILLED(f"MFAwesome keyboard interrupt: {e!r}") from e
    MFAExit()


def run(
    filterterm: str | None = None,
    configfile: Path | None = None,
    loglevel: int = 30,
    test: bool = False,
    encryptconfig: bool = False,
    decryptconfig: bool = False,
    exportconfig: Path | None = None,
    changepassword: bool = False,
    generateconfig: Path | None = None,
    printconfig: bool = False,
    searchsecrets: str | None = None,
    addsecrets: str | None = None,
    addqrsecrets: Path | None = None,
    generatesecret: bool = False,
    configdebug: bool = False,
    googleauthexport: str | Path | None = None,
    runtests: bool = False,
    version: bool = False,
    removesecret: str | None = None,
    continuous: bool = False,
    exact: bool = False,
    showsecrets: bool = True,
    noclearscreen: bool = False,
    now: bool = False,
    showerr: bool = False,
    timelimit: float | None = None,
    noendtimer: bool = False,
    hotp: bool = False,
):
    args = {
        "filterterm": filterterm,
        "configfile": configfile,
        "loglevel": loglevel,
        "test": test,
        "encryptconfig": encryptconfig,
        "decryptconfig": decryptconfig,
        "exportconfig": exportconfig,
        "changepassword": changepassword,
        "generateconfig": generateconfig,
        "printconfig": printconfig,
        "searchsecrets": searchsecrets,
        "addsecrets": addsecrets,
        "addqrsecrets": addqrsecrets,
        "generatesecret": generatesecret,
        "configdebug": configdebug,
        "googleauthexport": googleauthexport,
        "runtests": runtests,
        "version": version,
        "removesecret": removesecret,
        "continuous": continuous,
        "exact": exact,
        "showsecrets": showsecrets,
        "noclearscreen": noclearscreen,
        "now": now,
        "showerr": showerr,
        "timelimit": timelimit,
        "noendtimer": noendtimer,
        "hotp": hotp,
    }
    ValidateArguments(args)
    ######  FUNCTIONS THAT DO NOT REQUIRE CONFIG ACCESS ######
    # noconfigio = {"generatesecret", "configdebug", "runtests", "version"}
    # configdebug MUST be first

    if hotp:
        runhotp(configfile=configfile, filterterm=filterterm, exact=exact, showsecrets=showsecrets)
        return MFAExit()

    if configdebug:
        config.ConfigDebug(configfile)
        return MFAExit()

    if generatesecret:
        pad = "*" * 20
        printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
        printok(f"New randomly generated secret: {GenerateSecret()}")
        printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
        return MFAExit()

    if generateconfig:
        try:
            config.GenerateDefaultConfig(configfile=generateconfig)
        except exception.ConfigError as e:
            printerr(f"Error generating configfile {generateconfig}: {e!r}")
            return MFAExit(1)
        return MFAExit()

    if runtests:
        sys.exit(subprocess.run(["python3", Path(__file__).parent / "mfatests.py"], check=False).returncode)  # noqa: S603

    if version:
        print(colors("MAX_RED", __logo__))
        printnorm(f"MFAwesome Version {__version__} {__build_date__} {__url__}")
        # print(f"{__author__}  ({__author_email__})")
        return MFAExit()

    ######  FUNCTIONS THAT REQUIRE CONFIG ACCESS ######
    # requiresconfigio = {"encryptconfig", "decryptconfig", "exportconfig", "changepassword", "generateconfig", "printconfig", "searchsecrets", "addsecrets", "googleauthexport"}
    try:
        with ConfigIO(configfile=configfile) as configio:
            if exportconfig:
                configio.ExportConfig(exportfile=exportconfig)
                return MFAExit()

            if googleauthexport:
                if configio.secretscount == 0:
                    raise MFAwesomeError(f"The config file {configio.configfile!s} contains no secrets")
                filtered_secrets = SearchSecrets(filterterm=filterterm, secrets=configio.config["secrets"])
                printwarn("The following secrets will be exported in Google Authenticator format:")
                if len(filtered_secrets) > 10:
                    for fs in filtered_secrets:
                        printnorm(fs)
                else:
                    rich.print_json(json.dumps(filtered_secrets))
                if check_yes_no(printwarn("Are you sure you want to export all of these secrets?", retstr=True)):
                    ExportToGoogleAuthenticator(filtered_secrets, exportdir=googleauthexport)
                    printok("Secrets exported!")
                else:
                    printerr("Google authenticator export canceled")

                return MFAExit()

            if addqrsecrets:
                newsecrets = LoadQRSecrets(configio._config["secrets"], qrdir=addqrsecrets)
                configio.AddSecrets(newsecrets)
                return MFAExit()

            if addsecrets:
                try:
                    newsecrets = json.loads(addsecrets)
                except json.JSONDecodeError as e:
                    raise ArgumentError(
                        f'The provided secret could not be parsed: {addsecrets}\nUse this format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}',
                    ) from e
                configio.AddSecrets(newsecrets)
                return MFAExit()

            if encryptconfig:
                configio.EncryptConfigFile()
                return MFAExit()

            if decryptconfig:
                printnorm(f"Config loaded and decrypted.  Now decrypting config file {configio.configfile}. Requires password verification...")
                configio.DecryptConfigFile()
                return MFAExit()

            if changepassword:
                configio.ChangePassword()
                return MFAExit()

            if printconfig:
                PrintConfig(config=configio.config)
                return MFAExit()

            if searchsecrets:
                if configio.secretscount == 0:
                    raise MFAwesomeError(f"The config file {configio.configfile!s} contains no secrets")
                # if filterterm is None:
                #     printerr("'--searchsecrets'/-z requires a filter term")
                #     sys.exit(1)
                results = SearchSecrets(searchsecrets, secrets=configio.config["secrets"], exact=exact)
                if len(results) == 0:
                    printerr(f"No secrets found matching term: {filterterm}")
                    return MFAExit(1)
                rich.print_json(jsondump(results))
                return MFAExit()

            if removesecret:
                if configio.secretscount == 0:
                    raise MFAwesomeError(f"The config file {configio.configfile!s} contains no secrets")
                configio.RemoveSecret(removesecret)
                return MFAExit()

        ######  IF NOTHING ELSE WAS INVOKED, RUN NORMALLY  ######
        doexit = {
            "encryptconfig",
            "decryptconfig",
            "exportconfig",
            "changepassword",
            "generateconfig",
            "printconfig",
            "searchsecrets",
            "addsecrets",
            "generatesecret",
            "configdebug",
            "googleauthexport",
            "runtests",
            "version",
        }
        # if any(getattr(args, x) for x in doexit):
        if any(args.get(x) for x in doexit):
            raise ArgumentError("Cannot specify other functions in normal mode.  You should not see this")

        if version:
            print(mfawesome.__logor__)
            return MFAExit()
        _RunNormal(
            configio,
            filterterm=filterterm,
            continuous=continuous,
            exact=exact,
            showsecrets=showsecrets,
            noclearscreen=noclearscreen,
            now=now,
            showerr=showerr,
            timelimit=timelimit,
            noendtimer=noendtimer,
        )
    except exception.ScreenResizeError as e:
        exception.ScreenSafe()
    except KeyboardInterrupt as e:
        raise exception.KILLED(f"MFAwesome keyboard interrupt: {e!r}") from e

    # except TypeError as e:
    #     #traceback.print_exception(e)
    #     printerr(f"TypeError: {e!s}")
    except exception.ConfigNotFoundError:
        printerr("No config seems to exist, please run 'mfa --generateconfig' or 'mfa --configdebug' and see documentation")
        return MFAExit(1)
    except exception.ConfigError:
        printcrit("exec configerr")
        printerr("Config Error: please run 'mfa --generateconfig' or 'mfa --configdebug' and see documentation")
        return MFAExit(1)
    except exception.MFAwesomeError as e:
        printerr(f"MFAwesome error: {e!s}")
        if logger.level == 10:
            printcrit("Traceback being shown because logging mode is set to DEBUG")
            traceback.print_exception(e)
        return MFAExit(1)
    except Exception as e:
        exception.ScreenSafe()
        printcrit(f"MFAwesome Unhandled Exception: {e!r}")
        if logger.level == 10:
            printcrit("Traceback being shown because logging mode is set to DEBUG")
            traceback.print_exception(e)
        return MFAExit(1)
    finally:
        sys.stdout.write("\n")
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()

    # THESE FUNCTIONS NEED TO BE ADDED
    # if runtests:
    #     sys.exit(subprocess.run(["python3", Path(__file__).parent / "mfatests.py"], check=False).returncode)

    # if addqrsecrets:
    #     qrsupport, err = CheckQRImportSupport()
    #     if qrsupport is False:
    #         printerr(
    #             f"Required dependencies are missing for QR image support.  Try installing with 'pip install mfawesome[all]' or see the README.  The Zbar libary is required and must be installed externally - see https://github.com/mchehab/zbar: {err!r}",
    #         )
    #         sys.exit(1)

    # if hotp:
    #     totp.runhotp(configfile=configfile, filterterm=filterterm, exact=exact, showsecrets=showsecrets)
    #     return MFAExit()

    # try:
    #     with config.ConfigIO(configfile=configfile) as configio:
    #         eloglevel = loglevel if loglevel is not None else configio.config.get("loglevel")
    #         logutils.SetLoggingLevel(level=eloglevel)
    #         if (
    #             logutils.NormalizeLogLevel(logger.level) in ["DEBUG", 10]
    #             and configio.config.get("keylogprotection", False) is True
    #             and not check_yes_no(
    #                 colors("white_on_red", "Debug logging is enabled - it is STRONGLY discouraged to enable debug logging on a machine you do not trust (and may be logging command line output)!"),
    #             )
    #         ):
    #             sys.exit()

    #         if googleauthexport:
    #             filtered_secrets = SearchSecrets(filterterm=filterterm, secrets=configio.config["secrets"])
    #             printwarn("The following secrets will be exported in Google Authenticator format:")
    #             if len(filtered_secrets) > 10:
    #                 for fs in filtered_secrets:
    #                     printnorm(fs)
    #             else:
    #                 rich.print_json(json.dumps(filtered_secrets))
    #             if check_yes_no(printwarn("Are you sure you want to export all of these secrets?", retstr=True)):
    #                 qrcodes.ExportToGoogleAuthenticator(filtered_secrets, exportdir=googleauthexport)
    #                 printok("Secrets exported!")
    #             else:
    #                 printerr("Google authenticator export canceled")

    #             return MFAExit()

    #         if addqrsecrets:
    #             newsecrets = qrcodes.LoadQRSecrets(configio._config["secrets"], qrdir=addqrsecrets)
    #             configio.AddSecrets(newsecrets)
    #             return MFAExit()

    #         if addsecrets:
    #             try:
    #                 newsecrets = json.loads(addsecrets)
    #             except json.JSONDecodeError as e:
    #                 printerr(
    #                     f'The provided secret could not be parsed: {addsecrets}\nUse this format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}',
    #                 )
    #                 return MFAExit(1)
    #             configio.AddSecrets(newsecrets)
    #             return MFAExit()

    #         if encryptconfig:
    #             configio.EncryptConfigFile()
    #             return MFAExit()

    #         if decryptconfig:
    #             printnorm(f"Config loaded and decrypted.  Now decrypting config file {configio.configfile}. Requires password verification...")
    #             configio.DecryptConfigFile()
    #             return MFAExit()

    #         if changepassword:
    #             configio.ChangePassword()
    #             return MFAExit()

    #         if printconfig:
    #             config.PrintConfig(config=configio.config)
    #             return MFAExit()

    #         if exportconfig:
    #             configio.ExportConfig(exportfile=exportconfig)
    #             return MFAExit()

    #         if searchsecrets:
    #             if filterterm is None:
    #                 printerr("'--searchsecrets'/-z requires a filter term")
    #                 sys.exit(1)
    #             results = SearchSecrets(filterterm, secrets=configio.config["secrets"], exact=exact)
    #             if len(results) == 0:
    #                 printerr(f"No secrets found matching term: {filterterm}")
    #                 return MFAExit(1)
    #             rich.print_json(jsondump(results))
    #             return MFAExit()

    #         if removesecret:
    #             configio.RemoveSecret(removesecret)
    #             return MFAExit()

    #         secrets = configio.config["secrets"]

    #         if len(secrets) == 0:
    #             raise exception.ConfigError("There are no secrets added to the config file!")
    #     try:
    #         timeserver = configio.config.get("timeserver", None)
    #         timeserver = timeserver if timeserver else ntptime.LoadNTPServers()
    #         if continuous:
    #             totp.multitotp_continuous(
    #                 secrets,
    #                 timelimit=timelimit,
    #                 showsecrets=showsecrets,
    #                 showerr=showerr,
    #                 filterterm=filterterm,
    #                 clearscreen=not noclearscreen,
    #                 exact=exact,
    #                 timeservers=timeserver,
    #             )
    #         else:
    #             totp.multitotp(
    #                 secrets=secrets,
    #                 now=now,
    #                 showsecrets=showsecrets,
    #                 showerr=showerr,
    #                 endtimer=not noendtimer,
    #                 filterterm=filterterm,
    #                 clearscreen=not noclearscreen,
    #                 exact=exact,
    #                 timeservers=timeserver,
    #             )
    # except exception.ScreenResizeError as e:
    #     exception.ScreenSafe()
    # except KeyboardInterrupt as e:
    #     raise exception.KILLED(f"MFAwesome keyboard interrupt: {e!r}") from e

    # except TypeError as e:
    #     traceback.print_exception(e)
    #     printerr(f"ERROR: Ensure that you use an '=' for options that require it, i.e. --addqrsecrets=/some/dir: {e!s}")
    # except exception.ConfigNotFoundError:
    #     printerr("No config seems to exist, please run 'mfa --generateconfig' or 'mfa --configdebug' and see documentation")
    #     return MFAExit(1)
    # except exception.MFAwesomeError as e:
    #     printerr(f"MFAwesome error: {e!s}")
    #     if logger.level == 10:
    #         printcrit("Traceback being shown because logging mode is set to DEBUG")
    #         traceback.print_exception(e)
    #     return MFAExit(1)
    # except Exception as e:
    #     exception.ScreenSafe()
    #     printcrit(f"MFAwesome Unhandled Exception: {e!r}")
    #     if logger.level == 10:
    #         printcrit("Traceback being shown because logging mode is set to DEBUG")
    #         traceback.print_exception(e)
    #     return MFAExit(1)
    # finally:
    #     sys.stdout.write("\n")
    #     sys.stdout.write(SHOW_CURSOR)
    #     sys.stdout.flush()
    return None


if __name__ == "__main__":
    main()
