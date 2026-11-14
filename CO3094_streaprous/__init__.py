#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

import os as _os
import sys as _sys

_pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
if _pkg_dir not in _sys.path:
    _sys.path.insert(0, _pkg_dir)

from .apps.sampleapp import create_sampleapp
from .daemon.backend import create_backend
from .daemon.proxy import create_proxy
from .daemon.streaprous import StreapRous
from .daemon.response import Response
from .daemon.request import Request
from .daemon.httpadapter import HttpAdapter
from .daemon.dictionary import CaseInsensitiveDict
