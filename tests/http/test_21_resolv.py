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
import logging
import os
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
class TestResolv:

    # use .invalid host name that should never resolv
    def test_21_01_resolv_invalid_one(self, env: Env, httpd, nghttpx):
        count = 1
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = '5'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://test-{count}.http.curl.invalid/'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)

    # use .invalid host name, one after the other
    @pytest.mark.parametrize("delay_ms", [1, 50])
    def test_21_02_resolv_invalid_serial(self, env: Env, delay_ms, httpd, nghttpx):
        count = 10
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = '5'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.http.curl.invalid/' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True)
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)

    # use .invalid host name, parallel
    @pytest.mark.parametrize("delay_ms", [1, 50])
    def test_21_03_resolv_invalid_parallel(self, env: Env, delay_ms, httpd, nghttpx):
        count = 20
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = '5'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.http.curl.invalid/' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True, extra_args=[
            '--parallel'
        ])
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)
