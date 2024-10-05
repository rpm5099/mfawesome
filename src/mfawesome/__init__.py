#!/usr/bin/env python
#               ____
#    ____ ___  / __/___ __      _____  _________  ____ ___  ___
#   / __ `__ \/ /_/ __ `/ | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \
#  / / / / / / __/ /_/ /| |/ |/ /  __(__  ) /_/ / / / / / /  __/
# /_/ /_/ /_/_/  \__,_/ |__/|__/\___/____/\____/_/ /_/ /_/\___/
#

__title__ = "mfawesome"
__description__ = "2FA Authenticator Tool"
__url__ = "https://gitlab.com/robpersonal1/mfawesome"
__version__ = "0.0.29"
__build_date__ = "2024-8-29"
__author__ = "Rob Milloy"
__author_email__ = "rob@milloy.net"
__logo__ = r"""

              ____
   ____ ___  / __/___ __      _____  _________  ____ ___  ___
  / __ `__ \/ /_/ __ `/ | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \
 / / / / / / __/ /_/ /| |/ |/ /  __(__  ) /_/ / / / / / /  __/
/_/ /_/ /_/_/  \__,_/ |__/|__/\___/____/\____/_/ /_/ /_/\___/

"""
__logo__ += __description__ + "\n"
__logor__ = "\x1b[0;0;39m\x1b[1m\x1b[38;5;196m" + __logo__ + "\x1b[0;0;39m"


# __logor__ += __description__ + "\n"

from contextlib import suppress

from . import config, exception, exec_mfawesome, logutils, mfa_secrets, ntptime, qrcodes, totp, utils

with suppress(ImportError, ModuleNotFoundError, exception.DependencyMissingError):
    from . import qrcodes
