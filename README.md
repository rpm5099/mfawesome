
<div align="center">
    <h1><img src="https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/lock_logo_3d_400.png?raw=true"/></h1>
</div>

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/mfa_word_logo.png?raw=true)

# **MFAwesome: CLI Multi Factor Authenticaton**

# Summary

**MFAwesome** (MFA) is an open-source system cross-platform command line based multifactor authentication tool. It allows secure storage of your TOTP and HOTP secrets in a simple config file that can be exported for use even on systems you do not trust. It allows importing secrets via Google Authenticator QR codes.

MFA provides keylogger protection, fuzzy matching on secret names, multiple encryption options and automatic synchronization via public NTP servers (custom NTP sever can be set in the config). It is faster and easier for those accustomed to CLI than using an app on your phone. 

The bottom line is this: if both of your two factor authentication methods are available on your mobile device the second factor provides no security against an attacker with access to it.  


| :zap:  NOTE |
| ----------- |
Due to the large size of the dependencies required for python's [qreader](https://pypi.org/project/qreader/) package it is only installed by specifying  `pip install mfawesome[all]`. However without `qreader` you will not be able to import secrets via qrcodes.

# Preview

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/run_cont.png?raw=true)

# Issue Reporting

If you have any MF'ing issues with the MF'ing package contact the MF'ing author or submit an MF'ing ticket so he can make it ***MFAWesome***.

# Requirements

Python:

`python>=3.11`

Python Libraries `pip install mfawesome`:

- `rich` (CLI Display output)
- `pyyaml` (Config/Secrets storage)
- `cryptography` (Secrets encryption)
- `numpy` (math)
- `protobuf` (Google Authenticator QR Generation)
- `opencv-python` (Google Authenticator QR Generation)
- `qrcode[pil]` (QR Code Generation)

`pip install mfawesome[all]` Optional dependencies:

- `qreader` (QR Code Import)  *Note: This package has a large amount of dependencies*

| :zap:  NOTE |
| ----------- |
On Linux `libzbar0` is required to read QR codes - `sudo apt install libzbar0` or `sudo dnf install libzbar0`.  On Windows you may need to install [vcredist_x64.exe](https://www.microsoft.com/en-gb/download/details.aspx?id=40784).  See the [QReader homepage](https://github.com/Eric-Canas/qreader) for details.

# Installation

There are several methods to test/install MFAwesome on your system.

## PyPI: The standard way

MFAwesome is on `PyPI`. By using PyPI, you will be using the latest
stable version.

- To install MFAwesome, simply use `pip`:

`pip install --user mfawesome`

- For a full installation (with all features):

`pip install --user mfawesome[all]`

- To upgrade MFAwesome to the latest version:

`pip install --user --upgrade mfawesome`

- To install the latest development version:

`git clone git@github.com:rpm5099/mfawesome.git`

or...

`git clone https://github.com/rpm5099/mfawesome.git`

then ...

`cd mfawesome`

`python -m setup.py install`

# Config File

The config file is named `mfawesome.conf` by default.  This can be changed by specifying via environment variable.  It is formatted in [YAML](https://yaml.org/spec/1.2.2/).  It's location is checked for in the following resolution order which can be checked using `mfa config debug`:

1. MFAWESOME_CONFIG environment variable (full file name with path)
2. Local directory for mfawesome.conf
3. `~/mfawesome.conf` (profile home)
4. `~/.config/mfawesome/mfawesome.conf` (default location)
5. Provided as a command line argument using `mfa --configfile`

**ALL** secrets are entered in the config file, either manually while it is not encrypted or via the command line using `mfa secrets add` and `mfa secrets import` (removal via `mfa secrets remove`). Other metadata is fine to enter in the yaml config file and will be encrypted along with the secrets. The only *required* section in the config file is `secrets`.

`mfa secrets add` takes a single parameter which must be in the form of json/python dictionary, i.e.:

`{"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}`

The active config file in use can be located via `mfa config debug` (similar to `pip config debug`). The option `mfa secrets export` can be used to export the existing secrets in the config file in QR code format.

The option `mfa config print` can be used to \[decrypt\] and display the full config file (*subjecting it to command line output logging*).

A double underscore - `__disabled_secret` in the `secrets` section of the config will disable the TOTP/HOTP calculation for that secret.

# NTP Time Servers

A list of time servers to use can be specified either via the `NTP_SERVERS` environment variable or within the config file under the root as `timeserver` (see config options below).

:zap: Having the correct time is essential to ensuring that the 2FA codes provided are correct.  Most of the time they operate on 30 second intervals, so even a small difference in time between MFA and the authentication server is problematic.

# Environment Variables

All environment variables take precedence over the config file, but not over manually passed arguments.  Secrets cannot be stored in environment variables.

## MFAWESOME_CONFIG

The environment variable `MFAWESOME_CONFIG`, if set, will be used as the path to the config file.  If the file does not exist or is invalid an exception will be raised.

## MFAWESOME_PWD

The environment variable `MFAWESOME_PWD`, if set, will be used as the password to decrypt secrets.  An attempt to decrypt or export secrets will still request that the password be entered for validation.

:zap:  ***NOTE:*** *It is recommended to only store your password this way on machines that you trust.  Environment variables can be logged.*

## MFAWESOME_LOGLEVEL

If set `MFAWESOME_LOGLEVEL` will override the setting in the config file, but not the level passed as a command line argument using `--loglevel`.

## NTP_SERVERS

The environment variable `NTP_SERVERS` can be specified as a colon `:` separated list of NTP time servers.  If none of the specified NTP servers can be contacted MFAwesome will fall back to the local system time, which if incorrect, _will cause time based codes to be incorrect._  A warning will be displayed if this is the case.

## MFAWESOME_TEST

This environment variable is only used for testing, do not enable.

# Encryption Details

Password hashing is accomplished via
[Scrypt](https://www.tarsnap.com/scrypt/scrypt.pdf) and the encryption
cipher is
[ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
using the Python [Cryptography](https://cryptography.io/en/latest/)
library ([source](https://github.com/pyca/cryptography)) which uses [OpenSSL](https://www.openssl.org/)
because it is the de facto standard for cryptographic libraries and provides
high performance along with various certifications. More info on
[Poly1305](https://cr.yp.to/mac/poly1305-20050329.pdf) and
[ChaCha](https://cr.yp.to/chacha/chacha-20080128.pdf). Scrypt is purpose
built to be both (A) configurable in how much work is required to
calculate a hash and (B) computationally and/or memory expensive
(depending on settings). These algorithms are considered
state-of-the-art as of 2024. The following settings are used for Scrypt
password hashing:

- CPU cost: 2\*\*14
- Blocksize: 8
- Parallelization: 1

Salt, Chacha \"add\" and Chacha \"nonce\" are generated using `secrets.token_bytes(...)`.

# Other Config File Options

**keylogprotection**

Setting this option to [true]{.title-ref} will display a randomized set of characters each time it is used that are used to enter your password, ensuring that keystroke loggers record only random characters, rather than your password. This option is set by default when using `mfa config export`.  Note that `mfa config export` is for exporting the entire config file and `mfa secrets export` is for exporting specific secrets in QR code format.

**loglevel**

At the root level of the config file loglevel can be entered as either an integer or ascii value using `-L` (*Note: ASCII log levels are not case sensitive*):

| ASCII Log Level | Integer Log Level |
| :-------------- | ----------------: |
| DISABLED        |                 0 |
| DEBUG           |                10 |
| INFO            |                20 |
| WARNING         |                30 |
| ERROR           |                40 |
| CRITICAL        |                50 |


**timeserver**

If you would like to force MFAwesome to use a specific time server include it under the [timeserver]{.title-ref} field in the root of the config. Otherwise a saved list of known publicly available timeservers will be used. The use of a timerserver ensures that the program has accurate time for calculating time based authentication codes.

# Command Line Options

MFAwesome is executed by running `mfa` at command line. There are three optional arguments that apply to any `mfa` command, and they must be specified immediatly following `mfa`.  `--configfile` is used to override the default config and the `MFAWESOME_CONFIG` to use a specific config file for that execution only.  `-L` is used to set the log level.  `-T` is for test mode - *do not use as it could potentially expose secrets.*  

## Sub-Commands

There are five `mfa` subcommands some of which in turn have additional subcommands.  To reduce the keystrokes to display secrets the `run` subcommand is assumed if the first term after `mfa` is not one of the five subcommands. For example `mfa banksecret` is equivalent to running `mfa run banksecret`.  Similarly running that same command while specifying a config file and exact secrets matching would be `mfa --configfile someconfig.conf -e banksecrets` and `mfa --configfile someconfig.conf run -e banksecrets` respectively.  Note that the `-e` is actually an argument to `run`, and must be specified immediately following it.

`mfa -s` will show protected information about the secret including the raw TOTP code and password is stored.

| :exclamation:  WARNING |
| ---------------------- |
Showing secrets will subject the to viewing by others as well as terminal output logging. A warning is issued if the config option `keylogprotection: true` is set.
![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/run_show_secrets.png?raw=true)

`mfa -c`: Run and display codes for 90s (or whatever is specified as timeout)
![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/run_cont.png?raw=true)

```
$mfa run -h
usage: MFAwesome run [-h] [-c] [-e] [-s] [-l] [-n] [-E] [-t TIMELIMIT] [-N] [filterterm]

positional arguments:
  filterterm            Optional term to filter displayed secrets

options:
  -h, --help            show this help message and exit
  -c, --continuous      Enable continuous code display - default to 90 but add optional argument for otherwise
  -e, --exact           Disable fuzzy matching on secret filterterm
  -s, --showsecrets     Enable showing secrets - WARNING: this will reveal sensitive information on your screen
  -l, --noclearscreen   Disable clearing the screen before exit - WARNING - can leave sensitive data on the screen
  -n, --now             Get codes now even if they expire very soon. N/A for continuous.
  -E, --showerr         Show errors getting and parsing codes
  -t TIMELIMIT, --timelimit TIMELIMIT
                        Length of time to show codes continuously (Default 90.0 seconds)
  -N, --noendtimer      Disable countdown timer for codes, N/A for --continuous
```

- `hotp`: Same as run, except for HOTP codes.  Counters are automatically incremented when the HOTP codes are displayed.  They can be modified in the config file manually if necessary.

```
$mfa hotp -h
usage: MFAwesome hotp [-h] [-c] [-e] [-s] [filterterm]

positional arguments:
  filterterm         Optional term to filter displayed secrets

options:
  -h, --help         show this help message and exit
  -c, --continuous   Enable continuous code display - default to 90 but add optional argument for otherwise
  -e, --exact        Disable fuzzy matching on secret filterterm
  -s, --showsecrets  Enable showing secrets - WARNING: this will reveal sensitive information on your screen
```

- `config`: Commands related to config file management

```
$mfa config -h
usage: MFAwesome config [-h] <debug encrypt decrypt password print generate> ...

options:
  -h, --help            show this help message and exit

mfa config commands:
  <debug encrypt decrypt password print generate>
                        Config file operations
    generate            Generate a new config file in the default location '$HOME/.config/mfawesome/mfawesome.conf'
    encrypt             Encrypt secrets in config file (if not already encrypted)
    decrypt             Permanently decrypt secrets in config file (if encrypted)
    export              Export config to the specified file (required). Keylog protection will be enabled. Please see the documentation for details
    print               Print entire unencrypted config and exit
    debug               Show config file resolution details
    password            Change password for secrets - unencrypted secrets are never written to disk
```

- `secrets`: Commands related to managing secrets.

```
$mfa secrets -h
usage: MFAwesome secrets [-h] <search generate remove export import qread> ...

options:
  -h, --help            show this help message and exit

mfa secrets commands:
  <search generate remove export import qread>
                        Secrets operations
    search              Search through all secrets for a filtertem and display matching.
    generate            Generate and print an OTP secret key
    remove              Remove a secret by specifying the secret name
    export              Export codes in QR images to be scanned by Google Authenticator
    import              Import codes from QR images
    add                 Add new secret(s), must be in dict json format: {"secretname": {"totp":"SECRETCODE", "user":"theduke", "url":"www.example.com"}}. Multiple secrets are acceptable
    qread               Read QR image and output the raw data
```


`mfa config encrypt`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/encrypt.png?raw=true)

`mfa config decrypt`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/decrypt.png?raw=true)

`mfa config print`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/config_print.png?raw=true)

`mfa config debug`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/config_debug.png?raw=true)

`mfa hotp`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/hotp.png?raw=true)

| :exclamation:  WARNING |
| ---------------------- |
Running in debug mode can output sensitive information to the terminal and could potentially be logged. A warning is issued if the config option `keylogprotection: true` is set.

`mfa secrets search`

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/search_secrets.png?raw=true)

-   `--addqrsecrets TEXT`: The required term is the name of the directory containing screenshots/images of QR images from Google Authenticator (or other source) you wish to import to your config

| :exclamation:  WARNING |
| ---------------------- |
***MFAwesome makes every attempt to ensure that your secrets are cleared from the screen following execution unless you have explicitly enabled \'\--noclearscreen/-l\', including on keyboard interrupt (SIGINT signal). However, Ctrl+Z (SIGTSTP signal) will stop the processs without leaving python a chance to clear output.***

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/keyboard_interrupt.png?raw=true)

![image](https://github.com/rpm5099/mfawesome/blob/e22d7b1387ec9e6492e82327da3c17fd543c585d/images/finished_codes.png?raw=true)

# Running From a Jupyter Notebook

``` python
from mfawesome import mfa
mfa("run")
mfa("secrets export /tmp/mfa")
```
| :iphone: Mobile Import |
| ----------- |
`secrets export` run in Jupyter will display the QR images to scan for import into your mobile device

# License

MFAwesome is distributed under the license described in the `LICENSE` file.

# Author

Rob Milloy (\@rpm5099) <rob@milloy.net>
