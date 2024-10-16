from __future__ import annotations

import base64
import copy
import logging
import os
import random
import shutil
import traceback
import urllib
from contextlib import contextmanager, redirect_stderr, redirect_stdout, suppress
from typing import TYPE_CHECKING, NamedTuple

import cv2
import qrcode
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool, symbol_database
from google.protobuf.internal import builder as _builder
from rich import print as rprint

from mfawesome.exception import DependencyMissingError, ExternalDependencyError, Invalid2FACodeError, MFAwesomeError, QRScanError
from mfawesome.utils import (
    IncrementToDeconflict,
    IsBase32,
    IsIPython,
    PathEx,
    PercentDecode,
    RunOnlyOnce,
    b32decode,
    check_yes_no,
    colors,
    colorstring,
    filenametimestamp,
    makestr,
    print_with_sep_line,
    printcrit,
    printdbg,
    printerr,
    printnorm,
    printok,
    printwarn,
)

if TYPE_CHECKING:
    from pathlib import Path

    import google

with suppress(ImportError, ModuleNotFoundError):
    from qreader import QReader

if IsIPython():
    from IPython import get_ipython
    from IPython.display import HTML, clear_output, display

logger = logging.getLogger("mfa")

MAXQRSIZE = 0x91B


@contextmanager
def suppress_stderr():
    """A context manager that redirects stdout and stderr to devnull"""
    with open(os.devnull, "w") as fnull, redirect_stderr(fnull) as err:
        yield err


# https://github.com/digitalduke/otpauth-migration-decoder/blob/master/src/decoder.py
@RunOnlyOnce
def HOTPWarning(m) -> None:
    printcrit(m)


def Init_Otpauth_Migration() -> google.protobuf.message.Message:
    DESCRIPTOR = descriptor_pool.Default().AddSerializedFile(
        b'\n\x17otpauth-migration.proto\x12\x11otpauth_migration"\xa7\x05\n\x07Payload\x12@\n\x0eotp_parameters\x18\x01 \x03(\x0b\x32(.otpauth_migration.Payload.OtpParameters\x12\x0f\n\x07version\x18\x02 \x01(\x05\x12\x12\n\nbatch_size\x18\x03 \x01(\x05\x12\x13\n\x0b\x62\x61tch_index\x18\x04 \x01(\x05\x12\x10\n\x08\x62\x61tch_id\x18\x05 \x01(\x05\x1a\xf0\x01\n\rOtpParameters\x12\x0e\n\x06secret\x18\x01 \x01(\x0c\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x0e\n\x06issuer\x18\x03 \x01(\t\x12\x37\n\talgorithm\x18\x04 \x01(\x0e\x32$.otpauth_migration.Payload.Algorithm\x12\x35\n\x06\x64igits\x18\x05 \x01(\x0e\x32%.otpauth_migration.Payload.DigitCount\x12\x30\n\x04type\x18\x06 \x01(\x0e\x32".otpauth_migration.Payload.OtpType\x12\x0f\n\x07\x63ounter\x18\x07 \x01(\x03"y\n\tAlgorithm\x12\x19\n\x15\x41LGORITHM_UNSPECIFIED\x10\x00\x12\x12\n\x0e\x41LGORITHM_SHA1\x10\x01\x12\x14\n\x10\x41LGORITHM_SHA256\x10\x02\x12\x14\n\x10\x41LGORITHM_SHA512\x10\x03\x12\x11\n\rALGORITHM_MD5\x10\x04"U\n\nDigitCount\x12\x1b\n\x17\x44IGIT_COUNT_UNSPECIFIED\x10\x00\x12\x13\n\x0f\x44IGIT_COUNT_SIX\x10\x01\x12\x15\n\x11\x44IGIT_COUNT_EIGHT\x10\x02"I\n\x07OtpType\x12\x18\n\x14OTP_TYPE_UNSPECIFIED\x10\x00\x12\x11\n\rOTP_TYPE_HOTP\x10\x01\x12\x11\n\rOTP_TYPE_TOTP\x10\x02\x62\x06proto3',
    )
    PBUFF = {}
    _sym_db = symbol_database.Default()
    _builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, PBUFF)
    _builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "otpauth_migration_pb2", PBUFF)
    if _descriptor._USE_C_DESCRIPTORS is False:
        DESCRIPTOR._options = None
        PBUFF["_PAYLOAD"]._serialized_start = 47
        PBUFF["_PAYLOAD"]._serialized_end = 726
        PBUFF["_PAYLOAD_OTPPARAMETERS"]._serialized_start = 201
        PBUFF["_PAYLOAD_OTPPARAMETERS"]._serialized_end = 441
        PBUFF["_PAYLOAD_ALGORITHM"]._serialized_start = 443
        PBUFF["_PAYLOAD_ALGORITHM"]._serialized_end = 564
        PBUFF["_PAYLOAD_DIGITCOUNT"]._serialized_start = 566
        PBUFF["_PAYLOAD_DIGITCOUNT"]._serialized_end = 651
        PBUFF["_PAYLOAD_OTPTYPE"]._serialized_start = 653
        PBUFF["_PAYLOAD_OTPTYPE"]._serialized_end = 726
    # else:
    #    printdbg(f"Use C descriptors is enabled, does not matter")
    Payload = PBUFF["Payload"]
    return Payload()


# Google OTPAuth Migration Object
GOAMO = Init_Otpauth_Migration()


class AuthSecret(NamedTuple):
    secret: str | None = None
    name: str | None = None
    issuer: str | None = None
    algorithm: str = "SHA1"
    digits: int = 6
    type: str | None = None
    counter: int | None = None
    period: int | None = 30


def ParseQRUrl(otpauth_migration_url: str, nodecode: bool = False) -> list:
    urlcomp = urllib.parse.urlparse(otpauth_migration_url)
    # AuthSecret = namedtuple("AuthSecret", ["secret", "name", "issuer", "algorithm", "digits", "type", "count"])
    results = []
    # google authenticator
    if urlcomp.query.startswith("data="):
        payload = None
        payload = base64.b64decode(urllib.parse.unquote(urlcomp.query[5:]))
        otpauth_migration_obj = Init_Otpauth_Migration()
        otpauth_migration_obj.ParseFromString(payload)
        if nodecode:
            return otpauth_migration_obj.otp_parameters

        otpalgorithms = {
            None: "SHA1",
            GOAMO.ALGORITHM_UNSPECIFIED: "SHA1",
            GOAMO.ALGORITHM_SHA1: "SHA1",
            GOAMO.ALGORITHM_SHA256: "SHA256",
            GOAMO.ALGORITHM_SHA512: "SHA512",
            GOAMO.ALGORITHM_MD5: "MD5",
        }
        otpdigits = {None: 6, GOAMO.DIGIT_COUNT_UNSPECIFIED: 6, GOAMO.DIGIT_COUNT_SIX: 6, GOAMO.DIGIT_COUNT_EIGHT: 8}
        otptypes = {None: "NONE", GOAMO.OTP_TYPE_UNSPECIFIED: "UNSPECIFIED", GOAMO.OTP_TYPE_HOTP: "HOTP", GOAMO.OTP_TYPE_TOTP: "TOTP"}

        # HOTPWarning("HOTP QR CODES NOT COMPLETED YET")
        # DEBUG ONLY
        # logger.critical("REMOVEME")
        # return otpauth_migration_obj.otp_parameters
        for entry in otpauth_migration_obj.otp_parameters:
            secret = base64.b32encode(entry.secret).decode().strip("=")
            name = entry.name
            issuer = entry.issuer
            algorithm = otpalgorithms[entry.algorithm]
            digits = otpdigits[entry.digits]
            otptype = otptypes[entry.type]
            counter = None
            if otptype.lower() == "hotp":
                counter = getattr(entry, "counter", None)
            period = getattr(entry, "period", 30)
            results.append(AuthSecret(secret, name, issuer, algorithm, digits, otptype, counter, period))
    # qr code from site - i.e. docker
    # https://datatracker.ietf.org/doc/draft-linuxgemini-otpauth-uri/
    # https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    # otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
    elif urlcomp.scheme == "otpauth":
        querydict = urllib.parse.parse_qs(urlcomp.query)
        name = PercentDecode(urlcomp.path.strip("/"))
        logger.debug(f"{name=} {querydict=}")
        secret = querydict.get("secret")
        # if not secret:

        secret = secret[0]
        logger.critical(f"{secret=}")
        if not IsBase32(secret):
            logger.debug(f"Attempting to convert secret as it is not valid base32: {secret}")
            secret = makestr(base64.b32encode(secret[0].encode())).strip("=")
        issuer = None
        if "issuer" in querydict:
            issuer = querydict["issuer"][0]
        algorithm = "SHA1"
        if "algorithm" in querydict:
            algorithm = querydict["algorithm"][0]
        digits = 6
        if "digits" in querydict:
            digits = int(querydict["digits"][0])
        otptype = urlcomp.netloc
        counter = None
        if "counter" in querydict:
            counter = int(querydict["counter"][0])
        period = getattr(querydict, "period", 30)

        results.append(AuthSecret(secret, name, issuer, algorithm, digits, otptype, counter, period))
    else:
        raise MFAwesomeError(f"Unhandled qr code error: {urlcomp=}")

    return results


@suppress_stderr()
def ScanQRImage(filename: str | Path) -> tuple:
    filename = PathEx(filename)
    try:
        image = cv2.cvtColor(cv2.imread(str(filename)), cv2.COLOR_BGR2RGB)
        qreader = QReader()
        qrdata = qreader.detect_and_decode(image=image)
    except cv2.error as e:
        printwarn(f"Warning: Unable to extract QR images from {filename}, skipping.")
        return None
    return qrdata


@suppress_stderr()
def RawQRRead(filename: str | Path) -> list:
    filename = str(PathEx(filename))
    img = cv2.cvtColor(cv2.imread(filename), cv2.COLOR_BGR2RGB)
    qreader = QReader()
    return qreader.detect_and_decode(image=img)


def DisplayRawQR(filename: str | Path) -> None:
    try:
        qrdata = RawQRRead(filename)
        for entry in qrdata:
            try:
                rprint(ParseQRUrl(entry, nodecode=False))
            except KeyError as e:
                logger.debug(f"QRRead exception: {e!r}")
                try:
                    rprint(ParseQRUrl(entry, nodecode=True))
                except Exception as e1:
                    logger.debug(f"QRRead exception: {e1!r}")
    except Exception as e2:
        printerr(f"Failed to read QR image: {filename!s}")
        if logger.level == 10:
            traceback.print_exception(e2)


def ScanQRDir(qrdir: str | Path) -> dict:
    filenames = []
    image_extensions = [".jpeg", ".jpg", ".png", ".gif", ".tiff", ".bmp", ".raw", ".emf"]
    qrdir = PathEx(qrdir)
    if qrdir.is_file():
        filenames = [qrdir]
        if qrdir.suffix not in image_extensions:
            logger.warning(f"This may not be a valid image file with extension {qrdir.suffix}")
    elif qrdir.is_dir():
        filenames = [x for x in qrdir.iterdir() if x.suffix in image_extensions]
    if len(filenames) == 0:
        raise MFAwesomeError(f"No valid image file extensions found in {qrdir}")
    otpauths = []
    otpnames = []
    qrtexts = []
    for filename in filenames:
        try:
            qrurls = ScanQRImage(filename=filename)  # returns a tuple in case there is more than one QR code detected in the image
        except QRScanError as e:
            printwarn(f"Error scanning QR image file {filename}: {e!s}")
            continue

        if not qrurls:
            continue
        logger.debug(f"{filename=}  {qrurls=}")

        for qrurl in qrurls:
            try:
                qrtextl = ParseQRUrl(qrurl)

            except MFAwesomeError as e:
                printwarn(f"The file {filename} does not appear to contain a valid otpauth url")
                logger.debug(f"The file {filename} does not appear to contain a valid otpauth url: {e!r}")
                continue
            qrtexts.extend(qrtextl)
    qrtexts.sort(key=lambda x: x.name)
    for qrtext in qrtexts:
        gname = IncrementToDeconflict(qrtext.name, otpnames)
        if qrtext.name in otpnames:
            printwarn(f"Warning: Duplicate secret name {qrtext.name}, renaming to {gname}")
            qrtext._replace(name=gname)
        otpauths.append(qrtext)
        otpnames.append(qrtext.name)
    printok(f"Extracted {len(otpauths)} secrets from QR images in {qrdir!s}!")
    return otpauths


def QRExport(secrets: dict, exportdir: str | Path | None = None, max_secrets_per_qr: int = 5) -> list[str]:
    exportdir = exportdir if exportdir else PathEx(".")
    exportdir = PathEx(exportdir)
    if exportdir.is_file():
        raise OSError(f"Cannot use location as export directory, file exist with that name: {exportdir!s}")
    _GOAMO = Init_Otpauth_Migration()
    exportable = []
    otpalgorithms = {
        None: _GOAMO.ALGORITHM_SHA1,
        "SHA1": _GOAMO.ALGORITHM_SHA1,
        "SHA256": _GOAMO.ALGORITHM_SHA256,
        "SHA512": _GOAMO.ALGORITHM_SHA512,
        "MD5": _GOAMO.ALGORITHM_MD5,
    }
    otpdigits = {None: _GOAMO.DIGIT_COUNT_SIX, 6: _GOAMO.DIGIT_COUNT_SIX, 8: _GOAMO.DIGIT_COUNT_EIGHT}
    otptypes = {"hotp": _GOAMO.OTP_TYPE_HOTP, "totp": _GOAMO.OTP_TYPE_TOTP}
    exportable = []
    skipped = []
    for secretname, data in secrets.items():
        datakeys = {x.casefold() for x in data if isinstance(x, str)}
        if "hotp" in datakeys:
            try:
                b32decode(data["hotp"])
            except Invalid2FACodeError as e:
                printwarn(f"The HOTP secret {secretname} has an invalid HOTP code, skipping")
                continue
            required = {"hotp", "counter"}
            if not required.issubset(datakeys):
                printwarn(f"The HOTP secret {secretname} does not have a all required parameters ({required}), skipping")

                continue
            authsecret = AuthSecret(
                data["hotp"].strip("="),
                secretname,
                data.get("issuer"),
                otpalgorithms.get(data.get("algorithm", "SHA1")),
                otpdigits.get(data.get("digits", 6)),
                otptypes["hotp"],
                data["counter"],
                data.get("period", 30),
            )
            exportable.append(authsecret)
            printok(f"Exporting TOTP secret '{secretname}'...")
        elif "totp" in datakeys:
            try:
                b32decode(data["totp"])
            except Invalid2FACodeError as e:
                printwarn(f"The TOTP secret '{secretname}' has an invalid TOTP code, skipping")
                continue
            authsecret = AuthSecret(
                data["totp"].strip("="),
                secretname,
                data.get("issuer"),
                otpalgorithms.get(data.get("algorithm", "SHA1")),
                otpdigits.get(data.get("digits", 6)),
                otptypes["totp"],
                None,
                data.get("period", 30),
            )
            exportable.append(authsecret)
            printok(f"Exporting TOTP secret '{secretname}'...")
        else:
            skipped.append(secretname)
    if skipped:
        printwarn(f"{len(skipped)} non-OTP secrets were skipped: {skipped}")
    GOAMO = Init_Otpauth_Migration()
    goamos = []
    for i, export in enumerate(exportable):
        exsecret = GOAMO.OtpParameters()
        exsecret.name = export.name
        exsecret.secret = b32decode(export.secret)
        if export.issuer:
            exsecret.issuer = export.issuer
        exsecret.algorithm = export.algorithm
        exsecret.digits = export.digits
        exsecret.type = export.type
        if export.counter:
            exsecret.counter = export.counter
        # exsecret.period = export.period - google authenticator does not allow this field
        GOAMO.otp_parameters.append(exsecret)
        if i > 0 and i % max_secrets_per_qr == 0:
            goamos.append(GOAMO)
            GOAMO = Init_Otpauth_Migration()
    if len(GOAMO.otp_parameters) > 0:
        goamos.append(GOAMO)

    batchid = random.randint(0, 0x7FFFFFFF)  # noqa: S311
    mpayloads = []
    for i, goamo in enumerate(goamos):
        goamo.batch_id, goamo.batch_index, goamo.batch_size, goamo.version = (batchid, i, len(goamos), 1)
        params = {"data": base64.b64encode(goamo.SerializeToString())}
        otpauth_url = "otpauth-migration://offline?" + urllib.parse.urlencode(params)
        if len(otpauth_url) > MAXQRSIZE:
            printcrit(f"You're gonna have a problem, too much data for a qr code {len(otpauth_url)=} {MAXQRSIZE=}")
        mpayloads.append(otpauth_url)
    exportdir = PathEx(exportdir)
    qrfiles = []
    for i, mp in enumerate(mpayloads, 1):
        qrimg = qrcode.make(mp)
        exportdir.mkdir(parents=True, exist_ok=True)
        fout = exportdir / f"mfa_secrets_qr_export_{filenametimestamp()}_{i}.png"
        qrfiles.append(fout)
        qrimg.save(fout)
        if IsIPython():
            import IPython
            from IPython.core.display import HTML, display

            printok(f"MFAWESOME SECRETS EXPORT {i}:")
            display(qrimg.get_image())
    for qri in qrfiles:
        qri.chmod(0o600)
    print_with_sep_line(printok, f"Total of {len(exportable)} Secret(s) exported to {exportdir.resolve()!s}:", color="bold_green", above=True)
    for fn in qrfiles:
        tab = "\t"
        printok(f"{tab}{fn!s}")
    printwarn(f"XXXXRemember to delete the exported qr codes - the images are located in: {exportdir.resolve()!s}")
    return qrfiles


def ImportFromQRImage(qrdir: str | Path) -> dict:
    return ConvertAuthSecretsToDict(ScanQRDir(qrdir))


def ConvertAuthSecretsToDict(authsecrets: list[AuthSecret]) -> dict:
    secrets = {}
    for authsec in authsecrets:
        secrets[authsec.name] = {}
        if authsec.type.casefold() == "totp":
            secrets[authsec.name]["totp"] = authsec.secret
        elif authsec.type.casefold() == "hotp":
            secrets[authsec.name]["hotp"] = authsec.secret
            secrets[authsec.name]["counter"] = authsec.counter

        if authsec.issuer:
            secrets[authsec.name]["issuer"] = authsec.issuer
        if authsec.algorithm:
            secrets[authsec.name]["algorithm"] = authsec.algorithm
        if authsec.digits:
            secrets[authsec.name]["digits"] = authsec.digits
        if authsec.period:
            secrets[authsec.name]["period"] = authsec.period
    return secrets
