#      __  ____________
#     /  |/  / ____/   |_      _____  _________  ____ ___  ___
#    / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \
#   / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/
#  /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/
# ruff: noqa: W291

import importlib.metadata


def get_package_homepage(package_name):
    try:
        metadata = importlib.metadata.metadata(package_name)
        return metadata.get("Home-page", metadata.get("Project-URL"))
    except importlib.metadata.PackageNotFoundError:
        return None


meta = importlib.metadata.metadata("mfawesome")
__title__ = "MFAwesome"
__version__ = importlib.metadata.version("mfawesome")
__description__ = meta["Summary"]
__url__ = get_package_homepage("mfawesome")
__author__ = meta["Author"]
__author_email__ = meta["Author-email"]

__logo__ = r"""

     __  ____________                                             
    /  |/  / ____/   |_      _____  _________  ____ ___  ___      
   / /|_/ / /_  / /| | | /| / / _ \/ ___/ __ \/ __ `__ \/ _ \     
  / /  / / __/ / ___ | |/ |/ /  __(__  ) /_/ / / / / / /  __/     
 /_/  /_/_/   /_/  |_|__/|__/\___/____/\____/_/ /_/ /_/\___/   

"""
__logor__ = "\x1b[0;0;39m\x1b[1m\x1b[38;5;196m" + __logo__ + "\x1b[0;0;39m"

from contextlib import suppress

from . import config, exception, exec_mfawesome, logutils, mfa_secrets, ntptime, qrcodes, totp, utils

with suppress(ImportError, ModuleNotFoundError, exception.DependencyMissingError):
    from . import qrcodes

mfa = exec_mfawesome.main
