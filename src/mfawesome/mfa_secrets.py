from __future__ import annotations

import base64
import binascii
import copy
import datetime
import functools
import getpass
import hashlib
import logging
import os
import random
import secrets
import string
import sys
from typing import (
    Any,
    AnyStr,
    Literal,
    LiteralString,
    Self,
    TypeVar,
    Union,
)

import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from mfawesome import config
from mfawesome.exception import (
    ConfigError,
    Cryptography_Exceptions,
    CryptographyError,
    DecryptionError,
    EncryptionError,
    IncorrectPasswordOrSaltError,
    KeyGenerationError,
    StopIPython,
    xTestComplete,
    xTestFailError,
)
from mfawesome.utils import IsIPython, PrintStack, bytify, clear_output_line, clear_previous_line, colors, logprint, printcrit, printdbg, printerr, printok, printwarn, stripcolors

logger = logging.getLogger("mfa")


def MFAExit(code: int = 0, test: bool = False) -> None:
    if test and code == 0:
        printdbg("Ignoring exit in test mode")
        raise xTestComplete
    if test and code != 0:
        raise xTestFailError(f"Unknown test failure!")
    if IsIPython():
        raise StopIPython("Stop right there!")
    sys.exit(code)


def dohash(data, algorithm="sha512_256", rounds=1):
    if algorithm.lower() not in hashlib.algorithms_available:
        raise ConfigError(
            f"The hash algorithm {algorithm} is not available.  These are the available algorithms: {hashlib.algorithms_available}",
        )
    if isinstance(data, str):
        data = data.encode()
    result = data
    for _ in range(rounds):
        result = hashlib.md5(result).digest()
    return result


def stronghash(data):
    return dohash(data, algorithm="sha512_256", rounds=10**7)  # rounds=10 ** 6)


def returnstr(func):
    """
    Decorator to ensure a a single bytes return value is returned as a str
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if isinstance(result, (bytes, bytearray, memoryview)):
            result = result.decode(errors="backslashreplace")
        return result

    return wrapper


@bytify
@returnstr
def PadBase64(s):
    for n in range(4):
        try:
            fixed = s + b"=" * n
            result = base64.urlsafe_b64decode(fixed)
            return fixed, result
        except binascii.Error as e:
            if str(e) != "Incorrect padding":
                raise e
    raise ValueError(f"No valid padding found for {s}")


def KeylogProtection(
    description: str,
    color1: str = "DEBUG_BLUE",
    color2: str = "GREEN",
):
    printwarn("Keylog protection enabled in config!")
    numbersonly = False
    allowedvals = list(string.ascii_letters + string.digits + string.punctuation)
    randomvals = list(allowedvals)
    if numbersonly:
        allowedvals = list(string.digits)
        randomvals = list(allowedvals)
    random.shuffle(randomvals)
    maxcols = 32
    allowedvals_chunks = [allowedvals[i : i + maxcols] for i in range(0, len(allowedvals), maxcols)]
    randomvals_chunks = [randomvals[i : i + maxcols] for i in range(0, len(randomvals), maxcols)]
    chunks = [
        list(zip(achunk, rchunk, strict=False))
        for achunk, rchunk in zip(
            allowedvals_chunks,
            randomvals_chunks,
            strict=False,
        )
    ]

    if len(chunks[-1]) < len(chunks[0]):
        chunks[-1] = chunks[-1] + [
            (
                " ",
                " ",
            ),
        ] * (len(chunks[0]) - len(chunks[-1]))
    print(f"{colors(color1, 'For')}    {colors(color2, 'Enter')}        " * len(chunks))
    for i in range(len(chunks[0])):
        equals = "=="
        if chunks[2][i][0] == " ":
            equals = "  "
        print(
            f"{colors(color1, chunks[0][i][0])}  ==  {colors(color2, chunks[0][i][1])}            {colors(color1, chunks[1][i][0])}  ==  {colors(color2, chunks[1][i][1])}            {colors(color1, chunks[2][i][0])}  {equals}  {colors(color2, chunks[2][i][1])}",
        )
    entered = getpass.getpass(description)
    return "".join([allowedvals[randomvals.index(x)] for x in entered])


def GetPassword(getpassmsg: str, verify: bool = False, keylogprot: bool = False) -> str:
    p0 = None
    p1 = None
    if envpassword := os.environ.get("MFAWESOME_PASSWD"):
        logger.debug(f"Read password from environment: {envpassword}")
        p0 = envpassword
        if os.environ.get("MFAWESOME_TEST"):
            logger.debug(f"Skipping verification in test mode, returning test password from MFAWESOME_PASSWD env var {p0}")
            return p0
    getpassword = getpass.getpass
    if keylogprot:
        getpassword = KeylogProtection
    limit = 3
    count = 0
    while True:
        logger.debug(f"{count=} {limit=}")  # {p0=} {p1=}")
        if count >= limit:
            printerr("Unable to get matching passwords!")
            raise ConfigError("Unable to get matching passwords!")
        count += 1
        if not p0:
            p0 = getpassword(f"Enter {getpassmsg}: ")
        # clear_previous_line()
        entered = copy.copy(p0)
        if verify:
            # p1 = getpassword(f"VERIFY {getpassmsg}") if IsIpython() else getpassword(f"{colors('BOLD_UNDERLINE_RED', 'VERIFY')} {getpassmsg}: ")
            # p1 = getpassword(colors("BOLD_UNDERLINE_RED", f"VERIFY {getpassmsg}"))
            p1 = getpassword(f"{colors('BOLD_UNDERLINE_RED', 'VERIFY')} {getpassmsg}: ")
            if IsIPython():
                p1 = stripcolors(getpassmsg)
            # clear_previous_line()
            if p0 != p1:
                printwarn(f"Password verification failed, passwords do not match!")
                p0 = None
                p1 = None
                continue
            return p0
        return p0


def fixpass(p) -> bytes:
    if isinstance(p, (bytes, bytearray, memoryview)):
        return p
    if isinstance(p, str):
        return p.encode(errors="backslashreplace")
    if isinstance(p, int):
        return str(p).encode(errors="backslashreplace")
    raise ValueError(f"Cannot fixpass {p} with type {type(p)}")


@bytify
def md5sum(data):
    return hashlib.md5(data).hexdigest()


@bytify
def sha512sum(data):
    return hashlib.sha512(data).hexdigest()


@bytify
def sha256sum(data):
    return hashlib.sha256(data).hexdigest()


def EpochToDate(d):
    epochdt = datetime.datetime.fromtimestamp(d)
    return f"{epochdt:%Y-%m-%d %I:%M:%S%p %Z}"


def GenerateSecret(size: int = 32) -> None:
    return base64.b32encode(secrets.token_bytes(size)).rstrip(b"=").decode()


T = TypeVar("T", bound="ScryptChacha20Poly1305")


class ScryptChacha20Poly1305:
    """
    Class to perform Chacha20Poly1305 encryption using Scrypt password hashing.

    https://en.wikipedia.org/wiki/ChaCha20-Poly1305
    https://en.wikipedia.org/wiki/Scrypt
    """

    @bytify
    def __init__(
        self,
        password: bytes,
        salt: bytes | None = None,
        length: int = 32,
        cpucost: int = 2**14,
        blocksize: int = 8,
        parallelization: int = 1,
        nonce: bytes | None = None,
        chacha_add: bytes | None = None,
    ) -> None:
        # Random bytes parameters can NOT be initialized in arguments as that only happens once when class is defined!
        self.password = password
        self.salt = salt if salt is not None else secrets.token_bytes(16)
        self.length = length
        self.cpucost = cpucost
        self.blocksize = blocksize
        self.parallelization = parallelization
        self.nonce = nonce if nonce else secrets.token_bytes(12)
        self.chacha_add = chacha_add if chacha_add else secrets.token_bytes(256)
        self.key = None

    def Info(self) -> None:
        print(f"password: {self.password}")
        if self.salt:
            print(f"salt: {binascii.hexlify(self.salt)}")
        else:
            print("salt is None")
        if self.chacha_add:
            print(f"chacha_add: {binascii.hexlify(self.chacha_add)}")
        else:
            print("chacha_add is None")
        if self.key:
            print(f"key: {binascii.hexlify(self.key)}")
        else:
            print("key is None")

    def ValidateSelf(self) -> None:
        # logger.debug(f"{self.password=} {self.salt=} {self.length=} {self.cpucost=} {self.blocksize=} {self.parallelization=} {self.chacha_add=}")
        if not all(
            v is not None
            for v in [
                self.password,
                self.salt,
                self.length,
                self.cpucost,
                self.blocksize,
                self.parallelization,
                self.chacha_add,
            ]
        ):
            raise CryptographyError("Not all required fields have values been populated")

    @bytify
    @classmethod
    def Create(cls: type[T], password: bytes) -> Self:
        """
        Creates a new instance of the class with all of the same parameters except that
        the password can be changed.
        """
        return cls(password=password)

    @bytify
    @staticmethod
    def ScryptDerivePasswordKey(
        password: bytes,
        salt: bytes | None = None,
        length: int = 32,
        n: int = 2**14,
        r: int = 8,
        p: int = 1,
    ) -> tuple[bytes, bytes]:
        """
        https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
        https://www.tarsnap.com/scrypt/scrypt-slides.pdf

        salt (bytes) - A salt.
        length (int) - The desired length of the derived key in bytes.
        n (int) - CPU/Memory cost parameter. It must be larger than 1 and be a power of 2.
        r (int) - Block size parameter.
        p (int) - Parallelization parameter.
        """
        try:
            salt = salt if salt is not None else secrets.token_bytes(16)
            kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
            key = kdf.derive(password)
            return salt, key
        except Cryptography_Exceptions as e:
            raise KeyGenerationError(f"Failed to generate Scrypt key") from e

    @bytify
    def ChaCha20Poly1305_Encrypt(
        self,
        data: bytes,
    ) -> bytes:
        if self.key is None:
            _salt, self.key = ScryptChacha20Poly1305.ScryptDerivePasswordKey(
                password=self.password,
                salt=self.salt,
            )
        chacha = ChaCha20Poly1305(self.key)
        encrypted = chacha.encrypt(self.nonce, data, self.chacha_add)
        return b":".join(
            [base64.b64encode(x) for x in (self.salt, self.nonce, self.chacha_add, encrypted)],
        )

    @bytify
    def ChaCha20Poly1305_Decrypt(
        self,
        data: bytes,
    ) -> str:
        """Expects the data argument to contain colon separated hex encoded salt, nonce, add and encrypted message"""
        self.salt = None
        self.nonce = None
        self.chacha_add = None

        self.salt, self.nonce, self.chacha_add, encrypted = (base64.b64decode(x) for x in data.split(b":"))
        if self.key is None:
            if not self.salt:
                raise ValueError("You have to provide the key or the salt")
            _salt, self.key = ScryptChacha20Poly1305.ScryptDerivePasswordKey(
                password=self.password,
                salt=self.salt,
            )
        chacha = ChaCha20Poly1305(self.key)
        return chacha.decrypt(self.nonce, encrypted, self.chacha_add)

    @bytify
    def Encrypt(self, data: bytes) -> bytes:
        try:
            self.ValidateSelf()
            return self.ChaCha20Poly1305_Encrypt(data)
        except Cryptography_Exceptions as e:
            raise EncryptionError("Encryption failed!") from e

    @bytify
    def Decrypt(self, data: bytes) -> bytes:
        try:
            self.ValidateSelf()
            return self.ChaCha20Poly1305_Decrypt(data=data)
        except cryptography.exceptions.InvalidTag as e:
            raise IncorrectPasswordOrSaltError(
                "Cryptography error InvalidTag indicates incorrect password or salt",
            ) from e
        except Cryptography_Exceptions as e:
            raise DecryptionError("Decryption failed!") from e
