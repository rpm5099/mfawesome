#!/usr/bin/env python
#      __  ____________
#     /  |/  / ____/   |_      _____  _________  ____ ___  ___
#    / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \
#   / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/
#  /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/

__title__ = "mfawesome"
__description__ = "2FA CLI Authenticator Tool"
__author__ = "Rob Milloy"
__author_email__ = "rob@milloy.net"
__logo__ = r"""

     __  ____________                                             
    /  |/  / ____/   |_      _____  _________  ____ ___  ___      
   / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \     
  / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/     
 /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/   

"""
__logo__ += __description__ + "\n"
__logor__ = "\x1b[0;0;39m\x1b[1m\x1b[38;5;196m" + __logo__ + "\x1b[0;0;39m"


# __logor__ += __description__ + "\n"

from contextlib import suppress

from . import config, exception, exec_mfawesome, logutils, mfa_secrets, ntptime, qrcodes, totp, utils

with suppress(ImportError, ModuleNotFoundError, exception.DependencyMissingError):
    from . import qrcodes

mfa = exec_mfawesome.main
