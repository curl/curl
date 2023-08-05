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
#
import json
import logging
from typing import Optional, Tuple, List, Dict
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


class TestEyeballs:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    # download using only HTTP/3 on working server
    @pytest.mark.skipif(condition=not Env.have_h3(), reason=f"missing HTTP/3 support")
    def test_06_01_h3_only(self, env: Env, httpd, nghttpx, repeat):
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '3'

    # download using only HTTP/3 on missing server
    @pytest.mark.skipif(condition=not Env.have_h3(), reason=f"missing HTTP/3 support")
    def test_06_02_h3_only(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        r.check_response(exitcode=7, http_status=None)

    # download using HTTP/3 on missing server with fallback on h2
    @pytest.mark.skipif(condition=not Env.have_h3(), reason=f"missing HTTP/3 support")
    def test_06_03_h3_fallback_h2(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '2'

    # download using HTTP/3 on missing server with fallback on http/1.1
    @pytest.mark.skipif(condition=not Env.have_h3(), reason=f"missing HTTP/3 support")
    def test_06_04_h3_fallback_h1(self, env: Env, httpd, nghttpx, repeat):
        nghttpx.stop_if_running()
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain2, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '1.1'

    # make a successful https: transfer and observer the timer stats
    def test_06_10_stats_success(self, env: Env, httpd, nghttpx, repeat):
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[urln])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['time_connect'] > 0.0
        assert r.stats[0]['time_appconnect'] > 0.0

    # make https: to a hostname that tcp connects, but will not verify
    def test_06_11_stats_fail_verify(self, env: Env, httpd, nghttpx, repeat):
        curl = CurlClient(env=env)
        urln = f'https://not-valid.com:{env.https_port}/data.json'
        r = curl.http_download(urls=[urln], extra_args=[
            '--resolve', f'not-valid.com:{env.https_port}:127.0.0.1'
        ])
        r.check_response(count=1, http_status=0, exitcode=False)
        assert r.stats[0]['time_connect'] > 0.0    # was tcp connected
        assert r.stats[0]['time_appconnect'] == 0  # but not SSL verified

    # make https: to an invalid address
    def test_06_12_stats_fail_tcp(self, env: Env, httpd, nghttpx, repeat):
        curl = CurlClient(env=env)
        urln = f'https://not-valid.com:1/data.json'
        r = curl.http_download(urls=[urln], extra_args=[
            '--resolve', f'not-valid.com:{1}:127.0.0.1'
        ])
        r.check_response(count=1, http_status=None, exitcode=False)
        assert r.stats[0]['time_connect'] == 0     # no one should have listened
        assert r.stats[0]['time_appconnect'] == 0  # did not happen either

