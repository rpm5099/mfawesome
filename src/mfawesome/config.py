from __future__ import annotations

import copy
import functools
import gzip
import json
import logging
import os
import sys
import textwrap
from collections.abc import Callable
from contextlib import suppress
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import AnyStr, Optional, Tuple

from pathlib import Path

import rich.pretty
import yaml

from mfawesome.exception import ConfigError, ConfigNotFoundError, DependencyMissingError, EncryptionError, IncorrectPasswordOrSaltError, MFAwesomeError
from mfawesome.logutils import NormalizeLogLevel
from mfawesome.mfa_secrets import (
    GetPassword,
    ScryptChacha20Poly1305,
    bytify,
)

with suppress(ImportError, ModuleNotFoundError, DependencyMissingError):
    from mfawesome.qrcodes import ImportFromQRImage  # , Init_Otpauth_Migration, ScanQRDir
from mfawesome.utils import (
    FF,
    CheckFile,
    IncrementToDeconflict,
    PathEx,
    PrintStack,
    ValidateB32,
    bytifykw,
    check_yes_no,
    colors,
    fix_b32decode_pad,
    get_close_matches,
    makestr,
    print_sep_line,
    print_with_sep_line,
    printcrit,
    printerr,
    printnorm,
    printok,
    printwarn,
    resolvepath,
)

loglevels = {
    "NOTSET": 0,
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

logger = logging.getLogger("mfa")

EXAMPLE_CONFIG = {
    "loglevel": "INFO",
    "secrets": {
        "Example Secret": {
            "totp": "CVPAWFCOAOBXAINUMWPTAN44GIC5HWERK3DYC7OXEAKYDE46ZFNA",
            "user": "someuser",
            "password": "somepassword",
            "url": "https://madeupwebsite.com/login.html",
            "notes": ["whatever", "I", "want", "here"],
            "whateveriwant": "also here",
        },
        "BankSecret": {
            "totp": "7GGJRU64KGSTQZOKUYXTOPQ6XLUPAMAJ2F4EZLE43Q2SRDTRLFAQ",
            "user": "userx",
            "password": "1qaz2wsx",
            "notes": "2fa for my bank",
        },
        "__Disabled Secret": {
            "totp": "OC3NY75ZQGDZFISL3OMWK32CEFLQBM4D7RJ4MEFVFUQKFOKIAV6Q",
            "user": "disableduser",
            "password": "disabledpassword",
            "url": "https://disabled.com/login.html",
        },
        "testsecret1": {
            "totp": "3GWDRDWOQRUIVBG3ONPMPNFCSCX43YSECZ7T4C2MTNPKZTMNHYLA",
            "issuer": "theduke",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        },
        "testsecret2": {
            "totp": "7K2TEZJRPPVBKAGUNGWS7R4GM77FWYKMLUVMCXLUBYYADUTZLOGQ",
            "issuer": "theduke",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        },
        "testsecret3": {
            "hotp": "VR6FTRQP3NEWDESH7AFJ7LFBAI3OEZIEOGGG3Y27QUISHVZLLQEA",
            "counter": 12345,
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        },
        "example_hotp_secret": {
            "hotp": "3IWMLPFIZBYIOS7HRAAYENZGLEHUIUL5BYGWHVGGYJTMZVFL7GEQ",
            "counter": 1234,
            "notes": "The count will be automatically incremented",
        },
    },
    "keylogprotection": False,
    "timeserver": "time.cloudflare.com",
    "flags": {},
}

DEFAULT_CONFIG = {
    "loglevel": "INFO",
    "secrets": {
        "__Example": {
            "totp": "[secret totp code]",
            "user": "[some user]",
            "url": "https://www.madeupsite.org/login.html",
            "notes": ["whatever", "I", "want", "here"],
            "whateveriwant": "also here",
        },
    },
    "keylogprotection": False,
    "timeserver": "time.cloudflare.com",
    "flags": {},
}


def TestCheck() -> bool:
    testenv = os.environ.get("MFAWESOME_TEST", False)
    if testenv is False:
        return False
    logger.setLevel("DEBUG")
    return True


def ShowMFAConfigVars() -> None:
    evars = ["MFAWESOME_CONFIG", "MFAWESOME_PWD", "MFAWESOME_TEST", "NTP_SERVERS"]
    found = {}
    for v in evars:
        if v in os.environ:
            found[v] = os.environ[v]
    if found:
        logger.debug(f"MFA Environment variables found: {found}")


def ClearMFAConfigVars() -> None:
    evars = ["MFAWESOME_CONFIG", "MFAWESOME_PWD", "MFAWESOME_TEST", "NTP_SERVERS"]
    for v in evars:
        if v in os.environ:
            os.environ.pop(v)


def LoadQRSecrets(secrets: dict, qrdir: str, skipconfirm: bool = True) -> dict:
    otpauths = ImportFromQRImage(qrdir)
    printwarn(f"The following {len(otpauths)} secret(s) were found, review and confirm you would like to add them:")
    rich.print_json(json.dumps(otpauths))
    if not skipconfirm and not check_yes_no(colors("BOLD_ORANGE", "Add the above secrets?")):
        printnorm("NOT adding secrets")
        return {}
    logger.debug(f"{otpauths=}")
    secretscopy = copy.copy(secrets)
    current_secrets = set([x.get("totp", None) for x in secretscopy.values()] + [x.get("hotp", None) for x in secretscopy.values()])
    current_names = list(secretscopy.keys())
    newsecrets = {}
    for name, sdata in otpauths.items():
        scode = sdata.get("totp") or sdata.get("hotp")
        if scode and scode in current_secrets:
            logger.error(f"The secret for '{name}' is alredy in current secrets {scode}.  This secret will not be added!")
            continue
        if name in current_names:
            _name = IncrementToDeconflict(name, current_names)
            logger.warning(f"Secret name {name} already exists, renaming to {_name}")
            name = _name
        newsecrets[name] = sdata
        printok(f"Adding secret {name}")
    return newsecrets


def LocateConfig(configfile: str | Path | None = None, noerr: bool = False) -> Path:
    """
    Config location "mfawesome.conf" resolution order:
    - Passed directly via command line
    - MFAWESOME_CONFIG environment variable (full file name with path)
    - Local directory for mfawesome.conf
    - ~/mfawesome.conf (profile home)
    - ~/.config/mfawesome/mfawesome.conf
    """
    cfname = "mfawesome.conf"
    homedir = Path.home()
    cfname = Path(cfname)
    valid_config_file = None
    if CheckFile(configfile):
        valid_config_file = configfile
    elif "MFAWESOME_CONFIG" in os.environ:
        envcfname = os.environ.get("MFAWESOME_CONFIG")
        if not CheckFile(envcfname):
            msg = f"The environment variable 'MFAWESOME_CONFIG' is configured to point to a non-existent file: {envcfname}"
            if noerr:
                logger.debug(msg)
            else:
                # raise MFAwesomeError(msg)
                logger.warning(msg)
        logger.debug(f"Retrieved config file name from environment variable: {envcfname}")
        valid_config_file = envcfname
    elif CheckFile(cfname):
        valid_config_file = cfname
    elif CheckFile(homedir / cfname):
        valid_config_file = homedir / cfname
    elif CheckFile(homedir / ".config" / "mfawesome" / cfname):
        valid_config_file = homedir / ".config" / "mfawesome" / cfname

    if valid_config_file:
        return Path(valid_config_file)
    if noerr:
        return False
    printerr("Config not found, showing output of 'mfa --configdebug'")
    ConfigDebug()
    raise ConfigNotFoundError


def GenerateDefaultConfig(configfile: str | Path | None = None, example: bool = False) -> None:
    configfile = Path().home() / ".config/mfawesome/mfawesome.conf" if not configfile else PathEx(configfile)
    if configfile.is_dir():
        configfile = configfile / "mfawesome.conf"
    logger.debug(f"{configfile=}")
    if os.environ.get("MFAWESOME_TEST") == "1":
        example = True
    config = EXAMPLE_CONFIG if example else DEFAULT_CONFIG
    # if configfile is None:
    #    configfile = Path(os.environ["MFAWESOME_CONFIG"]) if "MFAWESOME_CONFIG" in os.environ else Path.home() / ".config/mfawesome/mfawesome.conf"
    configfile = Path(configfile)
    if configfile.exists():
        raise ConfigError(f"Proposed config file already exists: {configfile}.  To specify a different location add a filename parameter - 'mfa --generateconfig /some/path/mfawesome.conf'")
    configfile.parent.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Config file specified {configfile} does not exist.  Generating")
    WriteConfigFile(fname=str(configfile), config=config)
    printok(f"Default config generated: {configfile.resolve()}")


def ValidateConfig(config: dict, removedisabled: bool = False) -> dict:
    if "secrets" not in config:
        raise MFAwesomeError("The config is missing the 'secrets' parameter")
    if loglevel := config.get("loglevel"):  # noqa: SIM102
        if isinstance(loglevel, str):
            config["loglevel"] = NormalizeLogLevel(loglevel)
    disabled = []
    if removedisabled:
        for dis in list(config["secrets"].keys()):
            if dis.startswith("__"):
                config["secrets"].pop(dis)
                disabled.append(dis)
        if disabled:
            logger.warning(f"Removed disabled secrets: {disabled}")
    return config


def BoolValidateConfig(configfile: str, warnings: bool = True) -> Tuple[bool | None, Optional[str]]:
    try:
        if not CheckFile(configfile):
            return (None, "File does not exist")
        config = Readyaml(configfile)
        config = ValidateConfig(config, removedisabled=False)
        err = []
        if CheckSecretsEncrypted(config["secrets"]) is False:
            if warnings:
                printcrit(f"configfile is not encrypted {configfile}")
            err.append("Secrets are NOT encrypted")
        if isinstance(config["secrets"], dict) and len(config["secrets"]) == 0:
            err.append("The config file contains no secrets")
        if not err:
            return (True, None)
    except (MFAwesomeError, yaml.error.YAMLError) as e:
        return (False, str(e))
    else:
        return (True, ", ".join(err))


def ConfigDebug(cliconfig: str | Path | None = None) -> None:
    print_with_sep_line(printnorm, msg="Config resolution order - last valid config is selected...")
    cfname = "mfawesome.conf"
    homedir = Path.home()
    cfname = Path(cfname)
    results = []
    winner = None
    c = None

    def CheckConfig(index: int, cfgkey: str, path: Path, noexist_printfunc: Callable = printnorm) -> dict:
        valid, err = BoolValidateConfig(path, warnings=False)
        pathstr = f"({path!s})" if path else ""
        if valid is True:
            return {"index": index, "cfgkey": cfgkey, "printfunc": printok, "msg": f"{index}.  Valid {cfgkey} config found {pathstr}", "path": path, "valid": valid, "err": err}
        if valid is False:
            return {"index": index, "cfgkey": cfgkey, "printfunc": printerr, "msg": f"{index}.  Invalid {cfgkey} config found {pathstr}: {err}", "path": path, "valid": valid, "err": err}
        if valid is None:
            return {"index": index, "cfgkey": cfgkey, "printfunc": noexist_printfunc, "msg": f"{index}.  {cfgkey} config not found {pathstr}", "path": path, "valid": valid, "err": err}
        raise MFAwesomeError(f"BoolValidateConfig returned an invalid result (this should not happen): {valid=} {err=}")

    cfg_env_var = PathEx(os.environ.get("MFAWESOME_CONFIG"))
    cli_config = Path(cliconfig) if isinstance(cliconfig, str | Path) else None
    configs = [
        ("Default location", homedir / ".config" / "mfawesome" / cfname, printnorm),
        ("Home directory", resolvepath(homedir / cfname), printnorm),
        ("Local directory", Path.cwd() / cfname, printnorm),
        ("Environment variable MFAWESOME_CONFIG", cfg_env_var, printerr if cfg_env_var else printnorm),
        ("Command line argument", cli_config, printerr if cli_config else printnorm),
    ]
    results = []
    winner = None
    for i, (cfgkey, path, pf) in enumerate(configs):
        i = len(configs) - i
        result = CheckConfig(i, cfgkey, path, pf)
        if result["valid"]:
            winner = result
        results.append(result)
    if winner:
        winner["msg"] += "..........................✓ Selected config"

    for result in results:
        result["printfunc"](result["msg"])

    if winner:
        if not winner["err"]:
            printok(f"\nEffective config appears valid: {winner['path']!s}")
        else:
            printwarn(f"\nEffective config file is {winner['path']!s} and appears valid but had warnings: {winner['err']}")
        for i, r in enumerate(results):
            if r == winner:
                continue
            if r["valid"] and r["err"]:
                printwarn(f"Warning: Config file {r['path']} appears valid but had warnings: {r['err']}")
    else:
        printerr(f"\nNo valid config file found!")


def Readyaml(fname: Path | str) -> str:
    fname = PathEx(fname)
    data = fname.read_text()
    result = None
    try:
        result = yaml.safe_load(data)

        if isinstance(result, str):
            logger.debug(data[0:100])
            logger.debug(type(result))
            logger.debug(result[0:100])
            raise ConfigError(f"The yaml file {fname} had a parsing error, unable to render to dictionary")
    except yaml.scanner.ScannerError as e:
        try:
            result = yaml.safe_load(data.replace("\t", "  "))
        except Exception:
            raise ConfigError(f"Unhandled exception reading config file {fname!s}: {e!s}") from None
        printwarn(f"Invalid tab is present in config: {e!r}")
    return result


def Writeyaml(fname: str, data: str) -> None:
    Path(fname).write_text(yaml.safe_dump(data))


def ReadConfigFile(fname: str | Path | None = None, testmode: bool = False) -> AnyStr:
    fname = PathEx(fname)
    if not (fname.exists() or fname.is_file()):
        if testmode:
            return None
        import traceback

        traceback.print_stack()
        printcrit(f"HOW THE FUCK ARE WE HERE????: {testmode}")
        raise ConfigNotFoundError(f"READCONFIGFFILE The config file {fname!s} does not exist")
    Path.chmod(fname, 0o600)
    return Readyaml(fname)


def WriteConfigFile(fname: str | Path, config: dict) -> None:
    Writeyaml(fname, config)
    Path.chmod(fname, 0o600)


def FormatSecrets(secrets: dict) -> dict:
    secretscopy = copy.copy(secrets)
    for secret in secrets:
        if "totp" in secretscopy[secret]:
            secretscopy[secret]["totp"] = fix_b32decode_pad(secrets[secret]["totp"])
        if "hotp" in secretscopy[secret]:
            secretscopy[secret]["hotp"] = fix_b32decode_pad(secrets[secret]["hotp"])
    return secretscopy


def CheckSecretsEncrypted(secrets: dict) -> bool:
    return not isinstance(secrets, dict)


def FilterSecrets(secrets: dict) -> dict:
    disabled = []
    secretnames = list(secrets.keys())
    for secretname in secretnames:
        if secretname.startswith("__") or "totp" not in secrets[secretname]:
            disabled.append(secrets.pop(secretname))  # noqa: PERF401
    logger.debug(f"{len(disabled)} Secrets filtered by TOTP")
    return secrets


def SearchSecrets(filterterms: str | list, secrets: dict, exact: bool = False, slackfactor: float = 1.4, cutoff: float = 0.55) -> list:
    """
    slackfactor - LOWER means closer match
    cutoff - HIGHER means closer match (default for lib function is 0.4)
    """
    if filterterms in [None, [], ""]:
        return secrets
    if isinstance(filterterms, str):
        filterterms = [filterterms]

    def SearchSecrets(filterterm, rsecrets):
        slack = int(len(filterterm) * slackfactor)
        # cutoff = cutoff if len(filterterm) < 5 else 0.6
        logger.debug(f"{filterterm=} ({len(filterterm)}) {slack=} {slackfactor=} {cutoff=}")
        secretsraw = {}
        results = {}
        if exact:
            for k, v in rsecrets.items():
                secretsraw[k] = f"{k} {makestr(json.dumps(v))}"
            for k, v in secretsraw.items():
                if filterterm in v:
                    results[k] = rsecrets[k]
            return results
        filterterm = filterterm.lower()
        for k, v in rsecrets.items():
            secretsraw[k] = f"{k.lower()} {makestr(json.dumps(v)).lower()}"
        for k, v in secretsraw.items():
            if filterterm in v:
                results[k] = rsecrets[k]
                continue
            if len(filterterm) <= 4:
                continue
            searchvals = [v[i : i + slack + len(filterterm)] for i in range(len(v) - slack - len(filterterm))]
            matches = get_close_matches(filterterm, searchvals, n=1, cutoff=cutoff)
            if matches:
                results[k] = rsecrets[k]
        return results

    secrets_remaining = copy.copy(secrets)
    for ft in filterterms:
        secrets_remaining = SearchSecrets(ft, secrets_remaining)
    return secrets_remaining


class ConfigIO:
    @bytifykw("ipassword")
    def __init__(
        self,
        config: dict | None = None,
        configfile: str | Path | None = None,
        ipassword: str | None = None,
        maxtries: int = 3,
        decrypt: bool = True,
        getpassmsgstr: str = "MFAwesome secrets password",
    ):
        self.ipassword = ipassword if ipassword else os.environ.get("MFAWESOME_PWD")
        self.maxtries = maxtries
        self.decrypt = decrypt
        self.getpassmsgstr = getpassmsgstr
        self.secrets_encrypted = False
        self.test = bool(os.environ.get("MFAWESOME_TEST", False))
        logger.debug(f"{configfile=}")
        self.configfile = configfile if configfile else LocateConfig(noerr=self.test)
        if config is None:
            self._rawconfig = ReadConfigFile(fname=self.configfile, testmode=self.test)
        else:
            self._rawconfig = config
        self._config = copy.copy(self._rawconfig)
        self.secrets_encrypted_init = False
        if CheckSecretsEncrypted(self._rawconfig["secrets"]):
            self.secrets_encrypted_init = True
            self.secrets_encrypted = True
        self.keylogprot = self._rawconfig.get("keylogprotection", False)
        if self.secrets_encrypted and self.decrypt is True:
            if self.ipassword is None:
                self.ipassword = GetPassword(self.getpassmsgstr, verify=False, keylogprot=self.keylogprot)
            self.LoadConfig()
        else:
            self._config = self._rawconfig
        if self.config is None:
            raise ConfigError("No config successfully loaded!")
        self.config = ValidateConfig(self.config)
        self.secretscount = len(FilterSecrets(self.config["secrets"]))
        self._configbackup = self.config

    def ValidateArgs(self) -> bool:
        if self.permanent is False and self.writedecrypted is True:
            raise ConfigError(f"ConfigIO Error: Write decrypted config flag set but permanent flag is not.")
        return True

    @property
    def config(self) -> str:
        return copy.deepcopy(self._config)

    @config.setter
    def config(self, newconfig: dict) -> None:
        self._config = copy.deepcopy(newconfig)

    def LoadConfig(self) -> Optional[str]:
        if not self.config:
            raise ConfigNotFoundError("Config appears blank!")
        if not CheckSecretsEncrypted(self.config["secrets"]):
            printwarn(
                f"Your secrets are not encrypted (or there are none entered).  Secrets can be added to your config file at {self.configfile!s}\n\tStrongly consider protecting them by using 'mfa --encryptsecrets', especially if this is not a machine you fully control.",
            )
        if CheckSecretsEncrypted(self.config["secrets"]) is True and self.decrypt:
            for i in range(self.maxtries):
                if i > 0:
                    self.ipassword = GetPassword(getpassmsg=self.getpassmsgstr, verify=False, keylogprot=self._rawconfig.get("keylogprot", False))
                try:
                    config = self.DecryptSecrets()
                    break
                except IncorrectPasswordOrSaltError as e:
                    printerr("Password is incorrect, decryption failed...")
                    if i == self.maxtries - 1:
                        raise ConfigError("Max number of secret decryption attempts reached!") from e
                    continue
        if self.decrypt is True:
            config = ValidateConfig(config, removedisabled=False)
        self.config = config

    def ChangePassword(self) -> None:
        if CheckSecretsEncrypted(self.config):
            self.config = self.DecryptSecrets()
        else:
            printnorm("Config is not currently encrypted, but it will be now...")
        config = self.config
        self.ipassword = GetPassword(getpassmsg="Changed MFAwesome Password", verify=True, keylogprot=self._rawconfig.get("keylogprot", False))
        if self.ipassword == "":
            raise ConfigError(f"Password is blank.  Use 'mfa config decrypt' instead")
        config = self.EncryptConfig(force=True)
        WriteConfigFile(self.configfile, config)

    #################  Add filterterm
    def ExportConfig(self, exportfile: str | Path | None, filterterm: str | None = None, exact: bool = False) -> None:
        if exportfile is None:
            exportfile = "./exported_mfawesome.conf"
        exportfile = PathEx(exportfile)
        if exportfile.is_dir():
            exportfile = exportfile / "exported_mfawesome.conf"
        logger.debug(f"Exported config file: {exportfile}")
        if CheckSecretsEncrypted(self.config):
            self.config = self.DecryptSecrets()
        config = copy.deepcopy(self.config)
        if filterterm:
            printcrit("filtering secrets")
            config["secrets"] = SearchSecrets(filterterm, config["secrets"], exact=exact)
            printcrit(config["secrets"])
        self.ipassword = GetPassword(getpassmsg="Exported MFAwesome Password", verify=True, keylogprot=self._rawconfig.get("keylogprot", False))
        config = self.EncryptConfig(force=True, config=config)
        config["keylogprotection"] = True
        WriteConfigFile(exportfile, config)
        printok(f"MFAwesome config file exported to {exportfile!s}")

    def DecryptConfigFile(self, verify: bool = True) -> None:
        if not CheckSecretsEncrypted(self._rawconfig["secrets"]):
            printok("The config file is not currently encrypted")
            return
        self.config = self._rawconfig
        config = self.config
        self.ipassword = GetPassword("Config Decrypt Password", verify=True, keylogprot=self._rawconfig.get("keylogprot", False))
        config = self.DecryptSecrets()
        if verify and not TestCheck():
            if check_yes_no(colors("MAX_RED", f"You are about to decrypt your secrets and store them in the clear on this machine in {self.configfile}\n\tAre you sure? (y/n)")):
                WriteConfigFile(self.configfile, config)
                printok(f"Config file {self.configfile!s} decrypted!")
            else:
                printok("Config file secrets *NOT* decrypted!")
        else:
            WriteConfigFile(self.configfile, config)
            printok(f"Config file {self.configfile!s} decrypted!")
        self.config = config

    def EncryptConfigFile(self, getpassmsg: str = "new MFAwesome config encryption password", outfilename: str | Path | None = None, verify: bool = True, keylogprot: bool = False) -> None:
        outfilename = outfilename if outfilename else self.configfile
        config = ReadConfigFile(self.configfile, testmode=self.test)
        if outfilename == self.configfile and CheckSecretsEncrypted(config["secrets"]):
            printok(f"Config file {self.configfile} is already encrypted")
            return
        if not CheckSecretsEncrypted(config["secrets"]):
            self.ipassword = GetPassword(getpassmsg, verify=True, keylogprot=self._rawconfig.get("keylogprot", False))
        config = self.EncryptConfig(verify=verify, force=True)
        if keylogprot:
            config["keylogprotection"] = True
        WriteConfigFile(outfilename, config)
        printok(f"Config file {outfilename} written encrypted!")

    def DecryptSecrets(self) -> dict:
        configcopy = copy.deepcopy(self.config)
        encrypted_secrets = self.config.get("secrets")
        if not encrypted_secrets:
            raise MFAwesomeError("There are no secrets in config!")
        if not CheckSecretsEncrypted(encrypted_secrets):
            printwarn("Config Secrets are NOT currently encrypted!")
            return configcopy
        scpcrypt = ScryptChacha20Poly1305(self.ipassword)
        encrypted_secrets = "".join(encrypted_secrets).encode()
        decrypted_secrets = json.loads(gzip.decompress(scpcrypt.Decrypt(encrypted_secrets)))
        configcopy["secrets"] = decrypted_secrets
        logger.debug(f"{len(decrypted_secrets)} Secrets successfully decrypted")
        return configcopy

    def AddSecrets(self, newsecrets: dict) -> None:
        """
        Secret should be in the format of a dict with a single key and value of another dict that must ahve at least "totp" in it
        {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}
        """
        if not isinstance(newsecrets, dict):
            raise ConfigError(f"Added secrets must be of type dict, not {type(newsecrets)}")
        for secretkey, secretdata in newsecrets.items():
            if not isinstance(secretdata, dict):
                raise ConfigError(
                    f'Secret must be in the this format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}\n\tInvalid secret: {secretkey}:{secretdata}',
                )
            if "totp" not in secretdata and "hotp" not in secretdata:
                raise ConfigError(
                    f"Added secrets must have a 'totp' or 'hotp' key: {secretkey}:{secretdata}",
                )
            if secretkey in self._config["secrets"]:
                raise ConfigError(f"Cannot add secret with existing name: {secretkey}")
            self._config["secrets"][secretkey] = secretdata  # must use _config here to ensure that the nested dictionary secret gets updated
        printok(f"{len(newsecrets)} Secret(s) successfully added!")

    def RemoveSecret(self, secretname: str) -> None:
        if self.secretscount == 0:
            raise ConfigError(f"The config file {self.configfile} contains no secrets")
        if secretname not in self.config["secrets"]:
            raise ConfigError(f"The secret {secretname} does not exist!")
        Removed = {}
        Removed[secretname] = self._config["secrets"].pop(secretname)  # must use _config here to ensure that the nested dictionary secret gets updated
        printok(f"Secret removed: {Removed}")

    def EncryptConfig(self, password: str | None = None, verify: bool = False, force: bool = True, config: dict | None = None) -> None:
        configprovided = False
        if config:
            configprovided = True
        else:
            config = self.config
        if self.secrets_encrypted_init is False and force is False and not configprovided:
            logger.debug(f"Secrets were not encrypted, skipping...")
            return config
        if CheckSecretsEncrypted(config):
            logger.debug("Secrets are already encrypted!")
            return config
        configcopy = copy.deepcopy(config)
        password = password if password else self.ipassword
        current_secrets = FormatSecrets(configcopy["secrets"])
        invalid_secrets = []
        secret = None
        for name, secretdata in current_secrets.items():
            secret = secretdata.get("totp", None)
            if not secret:
                secret = secretdata.get("hotp", None)
            if not ValidateB32(secret) and secret is not None:
                invalid_secrets.append(name)
        if invalid_secrets:
            printwarn(f"Some secrets are invalid (but they will still be encrypted): {invalid_secrets}")
        scpcrypt = ScryptChacha20Poly1305(password=password)
        compsecrets = gzip.compress(json.dumps(configcopy["secrets"]).encode())
        encrypted_secrets = scpcrypt.Encrypt(compsecrets)
        final_encrypted_secrets = textwrap.wrap(encrypted_secrets.decode())
        if verify:
            # Run test to ensure that secrets decrypt successfully
            scpcrypt2 = ScryptChacha20Poly1305(password)
            encrypted_secrets2 = "".join(final_encrypted_secrets).encode()
            decrypted_secrets = json.loads(
                gzip.decompress(scpcrypt2.Decrypt(encrypted_secrets2)),
            )
            if decrypted_secrets != configcopy["secrets"]:
                raise EncryptionError(f"Encryption validation failed with password {password}- secrets NOT encrypted")
        configcopy["secrets"] = final_encrypted_secrets
        logger.debug("Config secrets encrypted!")
        return configcopy

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exception_type, _exception_value, _exception_traceback) -> None:
        if self.configfile is None:
            return
        if json.dumps(self._configbackup) != json.dumps(self.config):
            printwarn("Config has changed, updating config on disk now!")
            if not CheckSecretsEncrypted(self.config["secrets"]):
                self.config = self.EncryptConfig(force=False)
            WriteConfigFile(self.configfile, self.config)

    def __call__(self, func):
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            with self:
                return func(self, *args, **kwargs)

        return decorated


def PrintConfig(config: dict | None = None) -> None:
    printnorm(f"Showing active config file: {LocateConfig()}:")
    if config is not None:
        rich.print_json(json.dumps(config, indent=4), indent=4)
        return
    rich.print_json(json.dumps(GetConfig(), indent=4))


def LoadNTPServers(ntpservers: AnyStr | None = None) -> list[str] | None:
    if ntpservers is None:
        ntpservers = Path(__file__).parent / Path("data/ntpservers.yaml")
    # logger.debug(f"NTP servers data file: {ntpservers}")
    if CheckFile(ntpservers):
        return list(filter(None, Readyaml(Path.resolve(ntpservers))["NTPSERVERS"]))
    raise FileNotFoundError(f"The file {ntpservers} was not found!")


def GetConfig() -> dict:
    with ConfigIO(decrypt=True) as cfg:
        # return json.dumps(cfg.config, indent=4)
        return cfg.config
