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
import json
import logging
from typing import Optional, Tuple, List, Dict
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
@pytest.mark.skipif(condition=not Env.have_h3_server(),
                    reason=f"missing HTTP/3 server")
@pytest.mark.skipif(condition=not Env.have_h3_curl(),
                    reason=f"curl built without HTTP/3")
class TestEyeballs:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()

    # download using only HTTP/3 on working server
    def test_06_01_h3_only(self, env: Env, httpd, nghttpx, repeat):
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)
        assert r.stats[0]['http_version'] == '3'

    # download using only HTTP/3 on missing server
    def test_06_02_h3_only(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        assert r.exit_code == 7, f'{r}'  # could not connect

    # download using HTTP/3 on missing server with fallback on h2
    def test_06_03_h3_fallback_h2(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)
        assert r.stats[0]['http_version'] == '2'

    # download using HTTP/3 on missing server with fallback on http/1.1
    def test_06_04_h3_fallback_h1(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain2, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)
        assert r.stats[0]['http_version'] == '1.1'
