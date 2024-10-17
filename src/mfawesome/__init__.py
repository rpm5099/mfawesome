#!/usr/bin/env python
#      __  ____________
#     /  |/  / ____/   |_      _____  _________  ____ ___  ___
#    / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \
#   / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/
#  /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/

import importlib.metadata

meta = importlib.metadata.metadata("mfawesome")
__title__ = "MFAwesome"
__version__ = importlib.metadata.version("mfawesome")
__description__ = meta["Summary"]
__url__ = meta["Home-page"]
__author__ = meta["Author"]
__author_email__ = meta["Author-email"]

__logo__ = r"""

     __  ____________                                             
    /  |/  / ____/   |_      _____  _________  ____ ___  ___      
   / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \     
  / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/     
 /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/   

"""
# __logo__ += __description__ + "\n"
__logor__ = "\x1b[0;0;39m\x1b[1m\x1b[38;5;196m" + __logo__ + "\x1b[0;0;39m"


# __logor__ += __description__ + "\n"

from contextlib import suppress

from . import config, exception, exec_mfawesome, logutils, mfa_secrets, ntptime, qrcodes, totp, utils

with suppress(ImportError, ModuleNotFoundError, exception.DependencyMissingError):
    from . import qrcodes

mfa = exec_mfawesome.main
