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
import platform
from typing import Generator, Union

import pytest

from testenv.env import EnvConfig

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from testenv import Env, Nghttpx, Httpd, NghttpxQuic, NghttpxFwd


def pytest_report_header(config):
    # Env inits its base properties only once, we can report them here
    env = Env()
    report = [
        f'Testing curl {env.curl_version()}',
        f'  platform: {platform.platform()}',
        f'  curl: Version: {env.curl_version_string()}',
        f'  curl: Features: {env.curl_features_string()}',
        f'  curl: Protocols: {env.curl_protocols_string()}',
        f'  httpd: {env.httpd_version()}',
        f'  httpd-proxy: {env.httpd_version()}'
    ]
    if env.have_h3():
        report.extend([
            f'  nghttpx: {env.nghttpx_version()}'
        ])
    if env.has_caddy():
        report.extend([
            f'  Caddy: {env.caddy_version()}'
        ])
    if env.has_vsftpd():
        report.extend([
            f'  VsFTPD: {env.vsftpd_version()}'
        ])
    buildinfo_fn = os.path.join(env.build_dir, 'buildinfo.txt')
    if os.path.exists(buildinfo_fn):
        with open(buildinfo_fn, 'r') as file_in:
            for line in file_in:
                line = line.strip()
                if line and not line.startswith('#'):
                    report.extend([line])
    return '\n'.join(report)


@pytest.fixture(scope='session')
def env_config(pytestconfig, testrun_uid, worker_id) -> EnvConfig:
    env_config = EnvConfig(pytestconfig=pytestconfig,
                           testrun_uid=testrun_uid,
                           worker_id=worker_id)
    return env_config


@pytest.fixture(scope='session', autouse=True)
def env(pytestconfig, env_config) -> Env:
    env = Env(pytestconfig=pytestconfig, env_config=env_config)
    level = logging.DEBUG if env.verbose > 0 else logging.INFO
    logging.getLogger('').setLevel(level=level)
    if not env.curl_has_protocol('http'):
        pytest.skip("curl built without HTTP support")
    if not env.curl_has_protocol('https'):
        pytest.skip("curl built without HTTPS support")
    if env.setup_incomplete():
        pytest.skip(env.incomplete_reason())

    env.setup()
    return env


@pytest.fixture(scope='session')
def httpd(env) -> Generator[Httpd, None, None]:
    httpd = Httpd(env=env)
    if not httpd.exists():
        pytest.skip(f'httpd not found: {env.httpd}')
    httpd.clear_logs()
    assert httpd.initial_start()
    yield httpd
    httpd.stop()


@pytest.fixture(scope='session')
def nghttpx(env, httpd) -> Generator[Union[Nghttpx,bool], None, None]:
    nghttpx = NghttpxQuic(env=env)
    if nghttpx.exists() and env.have_h3():
        nghttpx.clear_logs()
        assert nghttpx.initial_start()
        yield nghttpx
        nghttpx.stop()
    else:
        yield False


@pytest.fixture(scope='session')
def nghttpx_fwd(env, httpd) -> Generator[Union[Nghttpx,bool], None, None]:
    nghttpx = NghttpxFwd(env=env)
    if nghttpx.exists():
        nghttpx.clear_logs()
        assert nghttpx.initial_start()
        yield nghttpx
        nghttpx.stop()
    else:
        yield False


@pytest.fixture(scope='session')
def configures_httpd(env, httpd) -> Generator[bool, None, None]:
    # include this fixture as test parameter if the test configures httpd itself
    yield True

@pytest.fixture(scope='session')
def configures_nghttpx(env, httpd) -> Generator[bool, None, None]:
    # include this fixture as test parameter if the test configures nghttpx itself
    yield True

@pytest.fixture(autouse=True, scope='function')
def server_reset(request, env, httpd, nghttpx):
    # make sure httpd is in default configuration when a test starts
    if 'configures_httpd' not in request.node._fixtureinfo.argnames:
        httpd.reset_config()
        httpd.reload_if_config_changed()
    if env.have_h3() and \
            'nghttpx' in request.node._fixtureinfo.argnames and \
            'configures_nghttpx' not in request.node._fixtureinfo.argnames:
        nghttpx.reset_config()
        nghttpx.reload_if_config_changed()
