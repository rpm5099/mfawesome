#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
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

with suppress(Exception):
    import argcomplete
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
from mfawesome.config import ConfigDebug, ConfigIO, FilterSecrets, GenerateDefaultConfig, LoadNTPServers, LoadQRSecrets, LocateConfig, PrintConfig, SearchSecrets, TestCheck
from mfawesome.exception import (
    KILLED,
    ArgumentError,
    ArgumentErrorIgnore,
    ConfigError,
    ConfigNotFoundError,
    DependencyMissingError,
    MFAwesomeError,
    QRImportNotSupportedError,
    ScreenResizeError,
    ScreenSafe,
    StopIPython,
    xTestFailError,
)
from mfawesome.logutils import NormalizeLogLevel, SetLoggingLevel, SetupLogging
from mfawesome.mfa_secrets import GenerateSecret
from mfawesome.qrcodes import DisplayRawQR, QRExport
from mfawesome.totp import multitotp, multitotp_continuous, runhotp
from mfawesome.utils import (
    SHOW_CURSOR,
    ANSIColors,
    CheckFile,
    CheckQRImportSupport,
    ErrorExitCleanup,
    IsIPython,
    PathEx,
    PathExFile,
    PrintList,
    PrintStack,
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
    from mfawesome.qrcodes import ImportFromQRImage

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("mfa")

CFGFILE = None


def MFAExit(code: int = 0) -> None:
    test = config.TestCheck()
    if test and code == 0:
        logger.debug("Ignoring exit in test mode")
        return code
    if test and code != 0:
        raise exception.xTestFailError(f"Non-zero exit code - Test failure!")
    if IsIPython():
        raise exception.StopIPython("Stop right there!")
    sys.exit(code)


def AddAlwaysArgs(parser):
    # Global arguments applicable to all commands
    parser.add_argument("--configfile", type=pathlib.Path, default=None, help="Specify config file with your secrets")
    parser.add_argument(
        "-L",
        "--loglevel",
        default="info",
        help="Set loglevel",
    )  # , choices=["0", "10", "20", "30", "40", "50", "NOTSET", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-T", "--test", action="store_true", help="Run in test mode - FOR DEBUGGING ONLY")
    return parser


def AddRunOnlyArgs(parser):
    parser.add_argument("filterterm", nargs="?", help="Optional term to filter displayed secrets")
    parser.add_argument("-c", "--continuous", action="store_true", help="Enable continuous code display - default to 90 but add optional argument for otherwise")
    parser.add_argument("-e", "--exact", action="store_true", help="Disable fuzzy matching on secret filterterm")
    parser.add_argument("-s", "--showsecrets", action="store_true", help="Enable showing secrets - WARNING: this will reveal sensitive information on your screen")
    parser.add_argument("-l", "--noclearscreen", action="store_true", help="Disable clearing the screen before exit - WARNING - can leave sensitive data on the screen")
    parser.add_argument("-n", "--now", action="store_true", help="Get codes now even if they expire very soon.  N/A for continuous.")
    parser.add_argument("-E", "--showerr", action="store_true", help="Show errors getting and parsing codes")
    parser.add_argument("-t", "--timelimit", type=float, default=90.0, help="Length of time to show codes continuously (Default 90.0 seconds)")
    parser.add_argument("-N", "--noendtimer", action="store_true", help="Disable countdown timer for codes, N/A for --continuous")
    # parser.add_argument("-H", "--hotp", action="store_true", help="Calculate HOTP codes, using a filterterm if supplied.  Counters will be incremented in the config")
    return parser


class ErrorCatchingArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, message=None):
        if status:
            raise ArgumentErrorIgnore(f"Invalid arguments for RunParser: {message}")

    def print_usage(self, _discard):
        return


def RunParser(rawargs):
    parser = ErrorCatchingArgumentParser(
        prog="MFAwesome Run",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{mfawesome.__logor__}\nDefault 'run' command implied.  MFAwesome Multifactor Authentication CLI tool.  Protect your secrets and access them easily. Run 'mfa'",
    )
    # Add always args
    parser = AddAlwaysArgs(parser)
    # Run only args
    parser = AddRunOnlyArgs(parser)
    if "argcomnplete" in globals():
        argcomplete.autocomplete(parser)
    try:
        args = parser.parse_args(rawargs)
    except ArgumentErrorIgnore as e:
        logger.debug(f"Got error running RunParser, falling back to full parsing mode: {type(e)=} {e!r}")
        return None
    logger.debug(f"Run parser result: {args}")
    return args


def Parse_Args(rawargs):
    # Separate arg parser for default run mode
    maincmds = ["run", "config", "secrets", "version", "hotp"]
    if not any([x in rawargs for x in ["-h", "--help"]]):
        try:
            args = RunParser(rawargs)
        except ArgumentErrorIgnore as e:
            logger.debug(f"MFA Run Argparse apparently not intended: {e!r}")
        if args is not None and args.filterterm not in maincmds:
            # return Run(args)
            return args
    logger.debug("falling back to full arg parsing")
    # Not a run command, do the full argument parsing
    parser = argparse.ArgumentParser(
        prog="MFAwesome",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{mfawesome.__logor__}\nMFAwesome Multifactor Authentication CLI tool.  Protect your secrets and access them easily. Run 'mfa'",
    )
    # Global arguments applicable to all commands
    parser = AddAlwaysArgs(parser)

    # Add Subparsers first level
    subparsers = parser.add_subparsers(title="MFA Commands", dest="mfa_command", metavar=f"<{' '.join(maincmds)}>")

    # run parser
    runparser = subparsers.add_parser("run", help="Run mfa and display codes")
    runparser = AddRunOnlyArgs(runparser)

    # version parser
    versionparser = subparsers.add_parser("version", help="Show version and exit")

    # HOTP parser
    hotpparser = subparsers.add_parser("hotp", help="Display HOTP codes")
    hotpparser.add_argument("filterterm", nargs="?", help="Optional term to filter displayed secrets")
    hotpparser.add_argument("-c", "--continuous", action="store_true", help="Enable continuous code display - default to 90 but add optional argument for otherwise")
    hotpparser.add_argument("-e", "--exact", action="store_true", help="Disable fuzzy matching on secret filterterm")
    hotpparser.add_argument("-s", "--showsecrets", action="store_true", help="Enable showing secrets - WARNING: this will reveal sensitive information on your screen")

    # config parser
    configparser = subparsers.add_parser("config", help="Config related sub-commands")
    # config subcommands
    config_metavar = "<debug encrypt decrypt password print generate>"
    config_subparsers = configparser.add_subparsers(title="mfa config commands", dest="config_command", help="Config file operations", metavar=config_metavar)
    genconfigparser = config_subparsers.add_parser("generate", help="Generate a new config file in the default location '$HOME/.config/mfawesome/mfawesome.conf'")
    genconfigparser.add_argument("outputconfigpath", nargs="?", help="Output location of the generated config file")
    encryptconfig_parser = config_subparsers.add_parser("encrypt", help="Encrypt secrets in config file (if not already encrypted)")
    decryptconfig_parser = config_subparsers.add_parser("decrypt", help="Permanently decrypt secrets in config file (if encrypted)")
    exportconfig_parser = config_subparsers.add_parser("export", help="Export config to the specified file (required).  Keylog protection will be enabled.  Please see the documentation for details")
    exportconfig_parser.add_argument("outputconfigpath", nargs="?", help="Exported config file path.  Defaults to local directory")
    exportconfig_parser.add_argument("filterterm", nargs="?", help="Optional term to filter exported secrets")
    exportconfig_parser.add_argument("-e", "--exact", action="store_true", help="Disable fuzzy matching on secret filterterm")
    printconfig_parser = config_subparsers.add_parser("print", help="Print entire unencrypted config and exit")
    debugconfig_parser = config_subparsers.add_parser("debug", help="Show config file resolution details")
    password_parser = config_subparsers.add_parser("password", help="Change password for secrets - unencrypted secrets are never written to disk")
    # secrets parser
    secretsparser = subparsers.add_parser("secrets", help="Secrets related sub-commands")
    secrets_metavar = "<search generate remove export import qread>"
    secrets_subparsers = secretsparser.add_subparsers(title="mfa secrets commands", dest="secrets_command", help="Secrets operations", metavar=secrets_metavar)
    # secrets subcommands
    searchsecrets_parser = secrets_subparsers.add_parser("search", help="Search through all secrets for a filtertem and display matching.")
    searchsecrets_parser.add_argument("searchterms", nargs="+", help="Search terms")
    searchsecrets_parser.add_argument("-e", "--exact", action="store_true", help="Disable fuzzy matching on secret filterterm")
    generate_parser = secrets_subparsers.add_parser("generate", help="Generate and print an OTP secret key")
    remove_parser = secrets_subparsers.add_parser("remove", help="Remove a secret by specifying the secret name")
    remove_parser.add_argument("secretname", help="Name of secret to be removed")
    export_parser = secrets_subparsers.add_parser("export", help="Export codes in QR images to be scanned by Google Authenticator")
    export_parser.add_argument("exportdir", nargs="?", type=PathEx, const=Path().cwd(), help="Directory to export Google Authenticator secrets to")
    export_parser.add_argument("-f", "--filterterm", "--filter", help="Optional filter term for exported secrets")
    import_parser = secrets_subparsers.add_parser("import", help="Import codes from QR images")
    import_parser.add_argument("importdir", type=PathEx, help="Add secrets from QR images by specifying directory containing the images.  Requires libzbar - https://github.com/mchehab/zbar")
    addsecret_parser = secrets_subparsers.add_parser(
        "add",
        help='Add new secret(s), must be in dict json format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}.  Multiple secrets are acceptable',
    )
    addsecret_parser.add_argument(
        "secrettext",
        help='Add new secret(s), must be in dict json format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}. Multiple secrets are acceptable',
    )
    qread_parser = secrets_subparsers.add_parser("qread", help="Read QR image and output the raw data")
    qread_parser.add_argument("qrfile", type=PathExFile, help="QR file name")
    if "argcomnplete" in globals():
        argcomplete.autocomplete(parser)
    args = parser.parse_args(rawargs)
    if args.mfa_command == "config" and args.config_command is None:
        raise ArgumentError(f"'mfa config' requires one of {config_metavar}")
    if args.mfa_command == "secrets" and args.secrets_command is None:
        raise ArgumentError(f"'mfa secrets' requires one of {secretsparser}")
    return args


class ConfigIORunWrapper:
    def __init__(self, args, validate_config: bool = True):
        self.args = args
        self.validate_config = validate_config

    def __enter__(self):
        self.configio = ConfigIO(configfile=self.args.configfile)
        if self.configio.secretscount == 0 and self.validate_config:
            printerr(f"The config file {PathEx(self.configio.configfile)!s} contains no enabled and valid secrets")
            return MFAExit(1)
        return self.configio

    def __exit__(self, exc_type, exc_value, tb):
        try:
            self.configio.__exit__(None, None, None)
            if exc_type is None:
                return True
            if exc_type is QRImportNotSupportedError:
                printerr(f"QR Import is not supported: {exc_type} {exc_value}")
            if exc_type is exception.ScreenResizeError:
                exception.ScreenSafe()
                return True
            if exc_type is KeyboardInterrupt:
                raise exception.KILLED(f"MFAwesome keyboard interrupt: {exc_type} {exc_value}")
            if exc_type is TypeError:
                printerr(f"TypeError: {exc_type} {exc_value!s}")
                if logger.level == 10:
                    print(tb, type(tb), dir(tb))
                    traceback.print_tb(tb)
                return MFAExit(1)
            if exc_type is exception.ConfigNotFoundError:
                printerr("No config seems to exist, please run 'mfa config generate' or 'mfa config debug' and see documentation")
                if logger.level == 10:
                    traceback.print_tb(tb)
                return MFAExit(1)
            if exc_type is exception.ConfigError:
                printerr("Config Error: please run 'mfa config generate' or 'mfa config debug' and see documentation")
                if logger.level == 10:
                    traceback.print_tb(tb)
                return MFAExit(1)
            if exc_type is exception.MFAwesomeError:
                printerr(f"MFAwesome error: {exc_type} {exc_value}")
                if logger.level == 10:
                    printcrit("Traceback being shown because logging mode is set to DEBUG")
                    traceback.print_tb(tb)
                return MFAExit(1)
            if exc_type is Exception:
                exception.ScreenSafe()
                printcrit(f"MFAwesome Unhandled Exception: {exc_type} {exc_value}")
                if logger.level == 10:
                    printcrit("Traceback being shown because logging mode is set to DEBUG")
                    traceback.print_tb(tb)
                return MFAExit(1)
        finally:
            sys.stdout.write("\n")
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()
        return False


def Run(args):
    with ConfigIORunWrapper(args) as configio:
        if configio.secretscount == 0:
            raise MFAwesomeError(f"The config file {configio.configfile!s} contains no secrets")
        if args.showsecrets:
            printwarn("WARNING: Enabled showing secrets - this will reveal sensitive information on your screen!")
        secrets = configio.config["secrets"]
        timeserver = configio.config.get("timeserver", None)
        timeserver = timeserver if timeserver else ntptime.LoadNTPServers()
        if args.continuous:
            totp.multitotp_continuous(
                secrets,
                timelimit=args.timelimit,
                showsecrets=args.showsecrets,
                showerr=args.showerr,
                filterterm=args.filterterm,
                clearscreen=not args.noclearscreen,
                exact=args.exact,
                timeservers=timeserver,
            )
        else:
            totp.multitotp(
                secrets=secrets,
                now=args.now,
                showsecrets=args.showsecrets,
                showerr=args.showerr,
                endtimer=not args.noendtimer,
                filterterm=args.filterterm,
                clearscreen=not args.noclearscreen,
                exact=args.exact,
                timeservers=timeserver,
            )
        MFAExit()


def main(rawargs: list | tuple | None = None):
    global logger
    rawargs = rawargs if rawargs is not None else sys.argv[1:]
    if isinstance(rawargs, str):
        rawargs = rawargs.split()
    elif not isinstance(rawargs, list | tuple):
        raise ArgumentError(f"Arguments provided to mfa main must be a str, list or tuple: {type(rawargs)}")
    args = Parse_Args(rawargs)
    logger = logutils.SetupLogging(level=args.loglevel)
    if "mfa_command" not in args.__dict__:
        logger.debug(f"Run mode enabled: {args}")
        Run(args)
        return MFAExit()
    if args.configfile is not None and not CheckFile(args.configfile):
        args.configfile = PathEx(args.configfile)
        raise ArgumentError(f"This config file does not exist: '{args.configfile}' ")

    if args.mfa_command == "version":
        print(colors("MAX_RED", __logo__))
        printnorm(f"MFAwesome Version {__version__} {__build_date__} {__url__}")
        print(f"{__author__}  ({__author_email__})")
        return MFAExit()

    if args.mfa_command == "config":
        logger.debug(f"config args: {args}")
        if args.config_command == "debug":
            config.ConfigDebug(args.configfile)
            return MFAExit()

        if args.config_command == "export":
            with ConfigIORunWrapper(args) as configio:
                configio.ExportConfig(args.outputconfigpath, args.filterterm, args.exact)
                return MFAExit()

        if args.config_command == "generate":
            try:
                GenerateDefaultConfig(args.outputconfigpath)
            except ConfigError as e:
                printerr(f"Error generating configfile!")
                return MFAExit(1)
            return MFAExit()

        if args.config_command == "encrypt":
            with ConfigIORunWrapper(args) as configio:
                configio.EncryptConfigFile()
            return MFAExit()

        if args.config_command == "decrypt":
            with ConfigIORunWrapper(args) as configio:
                configio.DecryptConfigFile()
            return MFAExit()

        if args.config_command == "password":
            with ConfigIORunWrapper(args) as configio:
                configio.ChangePassword()
            return MFAExit()

        if args.config_command == "print":
            PrintConfig(config=args.configfile)
            return MFAExit()

        printcrit(f"{args.config_command} not implemented!")
        MFAExit(1)

    if args.mfa_command == "secrets":
        if args.secrets_command == "search":
            with ConfigIORunWrapper(args) as configio:
                results = SearchSecrets(args.searchterms, secrets=configio.config["secrets"], exact=args.exact)
                if len(results) == 0:
                    printerr(f"No secrets found matching term(s): {args.searchterms}")
                else:
                    rich.print_json(jsondump(results))
            return MFAExit()

        if args.secrets_command == "generate":
            pad = "*" * 20
            printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
            printok(f"New randomly generated secret: {GenerateSecret()}")
            printwarn(f"{pad} PROTECTED SECRET - DO NOT SHARE! {pad}")
            return MFAExit()

        if args.secrets_command == "remove":
            with ConfigIORunWrapper(args) as configio:
                configio.RemoveSecret(args.secretname)
                return MFAExit()

        if args.secrets_command == "export":
            if args.exportdir is None:
                args.exportdir = Path().cwd()
            printnorm(f"Secrets will be exported to QR images in {args.exportdir!s}")
            with ConfigIORunWrapper(args) as configio:
                filtered_secrets = SearchSecrets(filterterms=args.filterterm, secrets=configio.config["secrets"])
                filtered_secrets = FilterSecrets(filtered_secrets)
                filtered_secrets = {x: y for x, y in filtered_secrets.items() if y.get("totp") or y.get("hotp")}
                if len(filtered_secrets) < 10:
                    printwarn("The following secrets will be exported in QR Image(s):")
                    rich.print_json(json.dumps(filtered_secrets))
                else:
                    printwarn(f"{len(filtered_secrets)} secrets will be exported to QR images")
                exportok = True if args.test else check_yes_no(printwarn("Are you sure you want to export all of these secrets?", retstr=True))
                if exportok:
                    QRExport(filtered_secrets, exportdir=args.exportdir)
                    printok("Secrets exported!")
                else:
                    printerr("Google authenticator export canceled")
            return MFAExit()

        if args.secrets_command == "import":
            qrsupport, err = CheckQRImportSupport()
            if not qrsupport:
                raise QRImportNotSupportedError
            with ConfigIORunWrapper(args, validate_config=False) as configio:
                newsecrets = LoadQRSecrets(configio._config["secrets"], qrdir=args.importdir, skipconfirm=args.test)
                configio.AddSecrets(newsecrets)
            return MFAExit()

        if args.secrets_command == "add":
            with ConfigIORunWrapper(args, validate_config=False) as configio:
                try:
                    newsecrets = json.loads(args.secrettext)
                except json.JSONDecodeError as e:
                    printerr(
                        f'The provided secret could not be parsed: {args.secrettext}\nUse this format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}',
                    )
                    return MFAExit(1)
                configio.AddSecrets(newsecrets)
                return MFAExit()

        if args.secrets_command == "qread":
            DisplayRawQR(args.qrfile)
            return MFAExit()

    if args.mfa_command == "hotp":
        runhotp(configfile=args.configfile, filterterm=args.filterterm, exact=args.exact, showsecrets=args.showsecrets)
        return MFAExit()

    if args.mfa_command == "run":
        logger.debug("mfa run normal")
        Run(args)
        MFAExit()

    if not args.test:
        printcrit(f"{args.mfa_command} not implemented!")
        raise MFAwesomeError("We really shouldnt get here")
    return 0


if __name__ == "__main__":
    sys.exit(main())
