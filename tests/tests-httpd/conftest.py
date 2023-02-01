#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2008 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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


def pytest_report_header(config, startdir):
    return f"curl tests-httpd tests"


def pytest_addoption(parser):
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))


@pytest.fixture(scope="package")
def env(pytestconfig) -> Env:
    env = Env(pytestconfig=pytestconfig)
    level = logging.DEBUG if env.verbose > 0 else logging.INFO
    logging.getLogger('').setLevel(level=level)
    env.setup()
    return env


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
    if env.have_h3_server():
        nghttpx = Nghttpx(env=env)
        nghttpx.clear_logs()
        assert nghttpx.start()
        yield nghttpx
        nghttpx.stop()
    return None

