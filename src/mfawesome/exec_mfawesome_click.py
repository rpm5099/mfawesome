#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import traceback
from contextlib import suppress
from pathlib import Path
from pprint import pformat, pprint
from typing import TYPE_CHECKING

import click
import rich

from mfawesome import (
    __author__,
    __author_email__,
    __build_date__,
    __description__,
    __logo__,
    __title__,
    __url__,
    __version__,
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
)

with suppress(ImportError, ModuleNotFoundError, DependencyMissingError):
    from mfawesome.qrcodes import ImportFromGoogleAuthenticator

if TYPE_CHECKING:
    from pathlib import Path

# if TYPE_CHECKING:


logger = logging.getLogger("mfa")


def MFAExit(code: int = 0) -> None:
    test = TestCheck()
    if test and code == 0:
        printdbg("Ignoring exit in test mode")
        return code
    if test and code != 0:
        raise TestFailError(f"Non-zero exit code - Test failure!")
    if IsIPython():
        raise StopIPython("Stop right there!")
    sys.exit(code)


@click.command()
# @click.group(context_settings={"max_content_width": shutil.get_terminal_size().columns - 10})
@click.pass_context
@click.argument("filterterm", nargs=1, required=False, default=None)
@click.option(
    "--configfile",
    is_flag=False,
    # default=None,
    type=click.Path(),
    required=False,
    help="Manually specify a config file to use",
)
@click.option(
    "--encryptconfig",
    "--encryptsecrets",
    is_flag=True,
    default=False,
    help="Encrypt secrets in config file (if not already encrypted)",
)
@click.option(
    "--decryptconfig",
    "--decryptsecrets",
    is_flag=True,
    default=False,
    help="Permanently decrypt secrets in config file (if encrypted)",
)
@click.option(
    "--exportconfig",
    is_flag=False,
    type=click.Path(),
    required=False,
    help="Export config to the specified file (required).  Keylog protection will be enabled.  Please see the documentation for details",
)
@click.option(
    "--changepassword",
    is_flag=True,
    default=False,
    help="Change password for secrets - unencrypted secrets are never written to disk",
)
@click.option(
    "--generateconfig",
    # is_flag=True,
    # default=False,
    type=click.Path(),
    help="Generate a new config file in the default location '$HOME/.config/mfawesome/mfawesome.conf' or argument to --generateconfig=/some/config/file - add your secrets there",
)
@click.option("--printconfig", is_flag=True, default=False)
@click.option(
    "--searchsecrets",
    "-z",
    is_flag=True,
    default=False,
    help="Search through all secrets for a filtertem and display matching.  '--exact' flag is applicable",
)
@click.option(
    "--addsecrets",
    help='Add new secret(s), must be in format of {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}.  Multiple secrets are acceptable',
)
@click.option("--removesecret", help="Remove a secret by specifying the secret name")
@click.option(
    "--addqrsecrets",
    help="Add secrets from QR images by specifying directory containing the images.  Requires libzbar - https://github.com/mchehab/zbar",
)
@click.option(
    "--generatesecret",
    is_flag=True,
    default=False,
    help="Generate and print a secret key and exit",
)
@click.option(
    "-c",
    "--continuous",
    is_flag=True,
    default=False,
    help="Enable continuous code display - default to 90 but add optional argument for otherwise",
)
@click.option(
    "-e",
    "--exact",
    is_flag=True,
    default=False,
    help="Disable fuzzy matching on secret filterterm",
)
@click.option(
    "-s",
    "--showsecrets",
    is_flag=True,
    default=False,
    help="Enable showing secrets - WARNING: this will reveal sensitive information on your screen",
)
@click.option(
    "-t",
    "--noendtimer",
    is_flag=True,
    default=False,
    help="Disable countdown timer for codes, N/A for --continuous",
)
@click.option(
    "-l",
    "--noclearscreen",
    is_flag=True,
    default=False,
    help="Disable clearing the screen before exit - WARNING - can leave sensitive data on the screen",
)
@click.option(
    "-n",
    "--now",
    is_flag=True,
    default=False,
    help="Get codes now even if they expire very soon.  N/A for continuous.",
)
@click.option(
    "-r",
    "--showerr",
    is_flag=True,
    default=False,
    help="Show errors getting codes",
)
@click.option(
    "--timelimit",
    nargs=1,
    required=False,
    type=float,
    default=90,
    help="Length of time to show codes continuously (seconds)",
)
@click.option(
    "--loglevel",
    nargs=1,
    required=False,
    default=None,
    help="Integer log level 0, 10, 20, 30, 40, 50",
)
@click.option("--configdebug", is_flag=True, help="Show config file resolution details")
@click.option(
    "--hotp",
    is_flag=True,
    help="Calculate HOTP codes, using a filterterm if supplied.  Counters will be incremented in the config",
)
@click.option(
    "--googleauthexport",
    default=None,
    # default=PathEx(".").resolve(),
    show_default=True,
    # nargs=1,
    is_flag=False,
    # is_flag=True,
    type=click.Path(),
    required=False,
    is_eager=False,
    help="Export codes in QR images to be scanned by Google Authenticator.  Set export dir via '--googleauthexport=/some/path/here' - default is current directory",
)
@click.option("-T", "--test", is_flag=True, default=False, help="Test mode")
@click.option("--runtests", is_flag=True, default=False, help="Run all tests")
@click.option("--version", is_flag=True, help="Show version information")
def main(ctx: click.core.Context, /, *args: list, **kwargs: dict) -> None:
    run(*args, **kwargs)


CFGFILE = None


def run(
    filterterm: str | None = None,
    configfile: str | None = None,
    encryptconfig: bool = False,
    decryptconfig: bool = False,
    exportconfig: str | Path | None = None,
    changepassword: bool = False,
    generateconfig: bool = False,
    printconfig: bool = False,
    searchsecrets: bool = False,
    addsecrets: dict | None = None,
    removesecret: str | None = None,
    addqrsecrets: str | None = None,
    generatesecret: bool = False,
    continuous: bool = False,
    exact: bool = False,
    showsecrets: bool = False,
    noendtimer: bool = False,
    noclearscreen: bool = False,
    now: bool = False,
    showerr: bool = False,
    timelimit: float = 90.0,
    loglevel: int | str = -1,
    configdebug: bool = False,
    hotp: bool = False,
    googleauthexport: str | Path | None = None,
    test: bool = False,
    runtests: bool = False,
    version: bool = False,
) -> None:
    global CFGFILE
    CFGFILE = configfile
    global logger
    if test is True:
        os.environ["MFAWESOME_TEST"] = "1"
    logger = SetupLogging(level=loglevel)

    if version:
        print(colors("MAX_RED", __logo__))
        printnorm(f"MFAwesome Version {__version__} {__build_date__} {__url__}")
        # print(f"{__author__}  ({__author_email__})")
        sys.exit()

    if runtests:
        sys.exit(subprocess.run(["python3", Path(__file__).parent / "mfatests.py"], check=False).returncode)

    if addqrsecrets:
        qrsupport, err = CheckQRImportSupport()
        if qrsupport is False:
            printerr(
                f"Required dependencies are missing for QR image support.  Try installing with 'pip install mfawesome[all]' or see the README.  The Zbar libary is required and must be installed externally - see https://github.com/mchehab/zbar: {err!r}",
            )
            sys.exit(1)

    if generateconfig:
        cfgfile = filterterm if filterterm else None
        if cfgfile is None:
            cfgfile = generateconfig if generateconfig else None
        try:
            GenerateDefaultConfig(configfile=cfgfile)
        except ConfigError as e:
            printerr(f"Error generating configfile {filterterm}: {e!r}")
            return MFAExit(1)
        return MFAExit()

    if configdebug:
        ConfigDebug(cliconfig=configfile)
        return MFAExit()

    if generatesecret:
        pad = "*" * 20
        printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
        printok(f"New randomly generated secret: {GenerateSecret()}")
        printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
        return MFAExit()

    if showsecrets:
        printwarn("WARNING: Enabled showing secrets - this will reveal sensitive information on your screen!")

    if hotp:
        runhotp(configfile=configfile, filterterm=filterterm, exact=exact, showsecrets=showsecrets)
        return MFAExit()

    try:
        with ConfigIO(configfile=configfile) as configio:
            eloglevel = loglevel if loglevel is not None else configio.config.get("loglevel")
            SetLoggingLevel(level=eloglevel)
            if (
                NormalizeLogLevel(logger.level) in ["DEBUG", 10]
                and configio.config.get("keylogprotection", False) is True
                and not check_yes_no(
                    colors("white_on_red", "Debug logging is enabled - it is STRONGLY discouraged to enable debug logging on a machine you do not trust (and may be logging command line output)!"),
                )
            ):
                sys.exit()

            if googleauthexport:
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
                    printerr(
                        f'The provided secret could not be parsed: {addsecrets}\nUse this format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}',
                    )
                    return MFAExit(1)
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

            if exportconfig:
                configio.ExportConfig(exportfile=exportconfig)
                return MFAExit()

            if searchsecrets:
                if filterterm is None:
                    printerr("'--searchsecrets'/-z requires a filter term")
                    sys.exit(1)
                results = SearchSecrets(filterterm, secrets=configio.config["secrets"], exact=exact)
                if len(results) == 0:
                    printerr(f"No secrets found matching term: {filterterm}")
                    return MFAExit(1)
                rich.print_json(jsondump(results))
                return MFAExit()

            if removesecret:
                configio.RemoveSecret(removesecret)
                return MFAExit()

            secrets = configio.config["secrets"]

            if len(secrets) == 0:
                raise ConfigError("There are no secrets added to the config file!")
        try:
            timeserver = configio.config.get("timeserver", None)
            timeserver = timeserver if timeserver else LoadNTPServers()
            if continuous:
                multitotp_continuous(
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
                multitotp(
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
        except ScreenResizeError as e:
            ScreenSafe()
        except KeyboardInterrupt as e:
            raise KILLED(f"MFAwesome keyboard interrupt: {e!r}") from e

    except TypeError as e:
        traceback.print_exception(e)
        printerr(f"ERROR: Ensure that you use an '=' for options that require it, i.e. --addqrsecrets=/some/dir: {e!s}")
    except ConfigNotFoundError:
        printerr("No config seems to exist, please run 'mfa --generateconfig' or 'mfa --configdebug' and see documentation")
        return MFAExit(1)
    except MFAwesomeError as e:
        printerr(f"MFAwesome error: {e!s}")
        if logger.level == 10:
            printcrit("Traceback being shown because logging mode is set to DEBUG")
            traceback.print_exception(e)
        return MFAExit(1)
    except Exception as e:
        ScreenSafe()
        printcrit(f"MFAwesome Unhandled Exception: {e!r}")
        if logger.level == 10:
            printcrit("Traceback being shown because logging mode is set to DEBUG")
            traceback.print_exception(e)
        return MFAExit(1)
    finally:
        sys.stdout.write("\n")
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()


if __name__ == "__main__":
    main()
