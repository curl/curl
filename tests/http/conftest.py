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
#
import logging
import os
import sys
from typing import Optional

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from testenv import Env, Nghttpx, Httpd


@pytest.fixture(scope="package")
def env(pytestconfig) -> Env:
    env = Env(pytestconfig=pytestconfig)
    level = logging.DEBUG if env.verbose > 0 else logging.INFO
    logging.getLogger('').setLevel(level=level)
    env.setup()
    return env

@pytest.fixture(scope="package", autouse=True)
def log_global_env_facts(record_testsuite_property, env):
    record_testsuite_property("http-port", env.http_port)


@pytest.fixture(scope='package')
def httpd(env) -> Httpd:
    httpd = Httpd(env=env)
    assert httpd.exists(), f'httpd not found: {env.httpd}'
    httpd.clear_logs()
    assert httpd.start()
    yield httpd
    httpd.stop()


@pytest.fixture(scope='package')
def nghttpx(env, httpd) -> Optional[Nghttpx]:
    nghttpx = Nghttpx(env=env)
    if env.have_h3():
        nghttpx.clear_logs()
        assert nghttpx.start()
    yield nghttpx
    nghttpx.stop()

