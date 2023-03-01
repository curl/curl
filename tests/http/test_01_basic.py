#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import pytest

from testenv import Env
from testenv import CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestBasic:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()

    # simple http: GET
    def test_01_01_http_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url)
        assert r.exit_code == 0
        assert r.response['status'] == 200
        assert r.json['server'] == env.domain1

    # simple https: GET, any http version
    def test_01_02_https_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_get(url=url)
        assert r.exit_code == 0
        assert r.response['status'] == 200
        assert r.json['server'] == env.domain1

    # simple https: GET, h2 wanted and got
    def test_01_02_h2_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2'])
        assert r.exit_code == 0
        assert r.response['status'] == 200
        assert r.response['protocol'] == 'HTTP/2'
        assert r.json['server'] == env.domain1

    # simple https: GET, h2 unsupported, fallback to h1
    def test_01_02_h2_unsupported(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain2}:{env.https_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2'])
        assert r.exit_code == 0
        assert r.response['status'] == 200
        assert r.response['protocol'] == 'HTTP/1.1'
        assert r.json['server'] == env.domain2

    # simple h3: GET, want h3 and get it
    @pytest.mark.skipif(condition=not Env.have_h3_curl(), reason="no h3 curl")
    @pytest.mark.skipif(condition=not Env.have_h3_server(), reason="no h3 server")
    def test_01_03_h3_get(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.h3_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http3'])
        assert r.exit_code == 0, f'{r}'
        assert r.response['status'] == 200
        assert r.response['protocol'] == 'HTTP/3'
        assert r.json['server'] == env.domain1
