from __future__ import annotations

import argparse
import json
import logging
import pathlib
import site
import sys
import traceback
from contextlib import suppress
from pathlib import Path
from pprint import pformat, pprint
from typing import TYPE_CHECKING, NoReturn

with suppress(Exception):
    import argcomplete
import rich

import mfawesome
from mfawesome import (
    __author__,
    __author_email__,
    __description__,
    __logo__,
    __title__,
    __url__,
    __version__,
    config,
    exception,
    logutils,
    totp,
)
from mfawesome.config import ConfigIO, FilterSecrets, GenerateDefaultConfig, LoadQRSecrets, PrintConfig, SearchSecrets
from mfawesome.exception import (
    ArgumentError,
    ArgumentErrorIgnore,
    ConfigError,
    MFAwesomeError,
    QRImportNotSupportedError,
)
from mfawesome.mfa_secrets import GenerateSecret
from mfawesome.ntptime import CorrectedTime
from mfawesome.qrcodes import ConvertAuthSecretsToDict, DisplayRawQR, ParseQRUrl, QRExport
from mfawesome.totp import runhotp
from mfawesome.utils import SHOW_CURSOR, CheckFile, IsIPython, PathEx, PathExFile, check_yes_no, colors, jsondump, printcrit, printerr, printnorm, printok, printwarn, suppress_stderr_stdout

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
    parser.add_argument("-T", "--testmode", action="store_true", help="Run in test mode - FOR DEBUGGING ONLY")
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
    return parser


class ErrorCatchingArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, message=None) -> NoReturn:
        if status:
            raise ArgumentErrorIgnore(f"Invalid arguments for RunParser: {message}")

    def print_usage(self, file):  # type: ignore  # noqa: ARG002
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
    try:
        args = parser.parse_args(rawargs)
    except ArgumentErrorIgnore as e:
        logger.debug(f"RunParser not implied by arguments, falling back to full parsing mode: {type(e)=} {e!r}")
        logger.debug(f"RunParser not implied by arguments, falling back to full parsing mode: {type(e)=} {e!r}")
        return None
    logger.debug(f"Run parser result: {args}")
    return args


def Parse_Args(rawargs):
    # Separate arg parser for default run mode
    maincmds = ["run", "config", "secrets", "version", "hotp", "clock", "tests"]
    args = None
    if not any(x in rawargs for x in ["-h", "--help"]):
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

    # test parser
    testparser = subparsers.add_parser("tests", help="Run MFAwesome tests via pytests")

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
    secrets_metavar = "<search generate remove export importqr importurl qread>"
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
    importqr_parser = secrets_subparsers.add_parser("importqr", help="Import codes from QR images")
    importqr_parser.add_argument("importdir", type=PathEx, help="Add secrets from QR images by specifying directory containing the images.")
    importjson_parser = secrets_subparsers.add_parser(
        "importjson",
        help='Add new secret(s), must be in dict json format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}.  Multiple secrets are acceptable',
    )
    importjson_parser.add_argument(
        "secrettext",
        help='Add new secret(s), must be in dict json format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}. Multiple secrets are acceptable',
    )
    importurl_parser = secrets_subparsers.add_parser(
        "importurl",
        help="Add new secret in url format: otpauth://totp/[NAME]]?secret=[TOTP/HOTP]&issuer=[ISSUERNAME]",
    )
    importurl_parser.add_argument("url", help="url format: otpauth://totp/[NAME]]?secret=[TOTP/HOTP]&issuer=[ISSUERNAME]")

    qread_parser = secrets_subparsers.add_parser("qread", help="Read QR image and output the raw data")
    qread_parser.add_argument("qrfile", type=PathExFile, help="QR file name")

    clockparser = subparsers.add_parser("clock", help="Display corrected time clock and system delta")
    clockparser.add_argument("n", nargs="?", type=int, default=180, help="Number of seconds to run the clock, default is 180s")

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
        # timeserver = configio.config.get("timeserver", None)
        # timeserver = timeserver if timeserver else config.LoadNTPServers()
        if args.continuous:
            totp.multitotp_continuous(
                secrets,
                timelimit=args.timelimit,
                showsecrets=args.showsecrets,
                showerr=args.showerr,
                filterterm=args.filterterm,
                clearscreen=not args.noclearscreen,
                exact=args.exact,
                timeservers=configio.timeserver,
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
                timeservers=configio.timeserver,
            )
        MFAExit()


def LocateMFATests():
    logutils.SetLoggingLevel(level="DEBUG")
    testmod = Path(next(iter(site.getsitepackages()))) / "mfawesome_tests/test_mfawesome.py"
    logger.debug(f"Checking if file exists:  {testmod}")
    if testmod.is_file():
        logger.debug(f"MFAwesome tests module found: {testmod!s}")
        return testmod

    logger.debug(f"Unable to find test_mfawesome.py in installed location, checking temporary install above {mfawesome.__file__=}...")
    mfapath = Path(mfawesome.__file__)
    for _ in range(len(mfapath.parts)):
        mfatests = mfapath / "../mfawesome_tests/test_mfawesome.py"
        if mfatests.is_file():
            logger.debug(f"MFA test file located at temporary install location: {mfatests!s}")
            return mfatests
        mfapath = mfapath.parent
    raise MFAwesomeError("Unable to find MFAwesome tests")


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
        printnorm(f"MFAwesome Version {__version__}   {__url__}")
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
                    err = f"{args.exact=} No secrets found matching term(s): {args.searchterms}"
                    if args.exact:
                        err += "   Try searching without the exact flag -e/--exact set"
                    printerr(err)
                    # printerr(f"No secrets found matching term(s): {args.searchterms}")

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
                exportok = True if args.testmode else check_yes_no(printwarn("Are you sure you want to export all of these secrets?", retstr=True))
                if exportok:
                    QRExport(filtered_secrets, exportdir=args.exportdir)
                    printok("Secrets exported!")
                else:
                    printerr("Google authenticator export canceled")
            return MFAExit()

        if args.secrets_command == "importurl":
            with ConfigIORunWrapper(args, validate_config=False) as configio:
                newsecrets = ConvertAuthSecretsToDict(ParseQRUrl(args.url))
                configio.AddSecrets(newsecrets)

        if args.secrets_command == "importqr":
            with ConfigIORunWrapper(args, validate_config=False) as configio:
                newsecrets = LoadQRSecrets(configio._config["secrets"], qrdir=args.importdir, skipconfirm=args.testmode)
                configio.AddSecrets(newsecrets)
            return MFAExit()

        if args.secrets_command == "importjson":
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

    if args.mfa_command == "clock":
        CorrectedTime().clock(n=args.n)
        return MFAExit()

    if args.mfa_command == "tests":
        printnorm("Running MFAwesome tests...")
        try:
            import pytest
        except ModuleNotFoundError as e:
            printerr("The pytest package must be installed to run test - 'pip install pytest'")
            return 1
        mfatests = str(LocateMFATests())
        logger.debug(f"Located mfa tests: {mfatests}")
        result = pytest.main([mfatests])
        if result != 0:
            printerr(f"MFAwesome tests failed - see pytest output for details")
            return result
        printok("All MFAwesome tests passed!")
        return result

    return 0


if __name__ == "__main__":
    sys.exit(main())
