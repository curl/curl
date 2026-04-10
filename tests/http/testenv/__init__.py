#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
# ruff: noqa: F401, E402
import pytest

pytest.register_assert_rewrite("testenv.env", "testenv.curl", "testenv.caddy",
                               "testenv.httpd", "testenv.nghttpx")

# This import must be first to avoid circular imports
from .curl import CurlClient, ExecResult, RunProfile  # noqa: I001

from .caddy import Caddy
from .certs import Credentials, TestCA
from .client import LocalClient
from .dante import Dante
from .dnsd import Dnsd
from .env import Env
from .httpd import Httpd
from .nghttpx import Nghttpx, NghttpxFwd, NghttpxQuic
from .sshd import Sshd
from .vsftpd import VsFTPD
