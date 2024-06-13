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
import sys, os

sys.path.append(os.path.join(os.path.dirname(__file__), 'http'))

from testenv import Env


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


def pytest_addoption(parser):
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')


def pytest_generate_tests(metafunc):
    if "repeat" in metafunc.fixturenames:
        count = int(metafunc.config.getoption("repeat"))
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('repeat', range(count))
