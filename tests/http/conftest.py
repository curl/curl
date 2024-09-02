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

from testenv import Env, Nghttpx, Httpd, NghttpxQuic, NghttpxFwd

def pytest_report_header(config):
    # Env inits its base properties only once, we can report them here
    env = Env()
    report = [
        f'Testing curl {env.curl_version()}',
        f'  httpd: {env.httpd_version()}, http:{env.http_port} https:{env.https_port}',
        f'  httpd-proxy: {env.httpd_version()}, http:{env.proxy_port} https:{env.proxys_port}'
    ]
    if env.have_h3():
        report.extend([
            f'  nghttpx: {env.nghttpx_version()}, h3:{env.https_port}'
        ])
    if env.has_caddy():
        report.extend([
            f'  Caddy: {env.caddy_version()}, http:{env.caddy_http_port} https:{env.caddy_https_port}'
        ])
    if env.has_vsftpd():
        report.extend([
            f'  VsFTPD: {env.vsftpd_version()}, ftp:{env.ftp_port}, ftps:{env.ftps_port}'
        ])
    return '\n'.join(report)

# TODO: remove this and repeat argument everywhere, pytest-repeat can be used to repeat tests
def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        metafunc.parametrize('repeat', [0])

@pytest.fixture(scope="package")
def env(pytestconfig) -> Env:
    env = Env(pytestconfig=pytestconfig)
    level = logging.DEBUG if env.verbose > 0 else logging.INFO
    logging.getLogger('').setLevel(level=level)
    if not env.curl_has_protocol('http'):
        pytest.skip("curl built without HTTP support")
    if not env.curl_has_protocol('https'):
        pytest.skip("curl built without HTTPS support")
    if env.setup_incomplete():
        pytest.skip(env.incomplete_reason())

    env.setup()
    if not env.make_clients():
        pytest.exit(1)
    return env

@pytest.fixture(scope="package", autouse=True)
def log_global_env_facts(record_testsuite_property, env):
    record_testsuite_property("http-port", env.http_port)


@pytest.fixture(scope='package')
def httpd(env) -> Httpd:
    httpd = Httpd(env=env)
    if not httpd.exists():
        pytest.skip(f'httpd not found: {env.httpd}')
    httpd.clear_logs()
    if not httpd.start():
        pytest.fail(f'failed to start httpd: {env.httpd}')
    yield httpd
    httpd.stop()


@pytest.fixture(scope='package')
def nghttpx(env, httpd) -> Optional[Nghttpx]:
    nghttpx = NghttpxQuic(env=env)
    if env.have_h3():
        nghttpx.clear_logs()
        assert nghttpx.start()
    yield nghttpx
    nghttpx.stop()

@pytest.fixture(scope='package')
def nghttpx_fwd(env, httpd) -> Optional[Nghttpx]:
    nghttpx = NghttpxFwd(env=env)
    if env.have_h3():
        nghttpx.clear_logs()
        assert nghttpx.start()
    yield nghttpx
    nghttpx.stop()
