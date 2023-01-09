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
from typing import Optional
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestDownload:

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_01_download_1(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_responses(count=1, exp_status=200)

    # download 2 files
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_02_download_2(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_responses(count=2, exp_status=200)

    # download 100 files sequentially
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_03_download_100_sequential(self, env: Env,
                                           httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-99]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_responses(count=100, exp_status=200)
        assert len(r.stats) == 100, f'{r.stats}'
        # http/1.1 sequential transfers will open 1 connection
        assert r.total_connects == 1

    # download 100 files parallel
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_04_download_100_parallel(self, env: Env,
                                         httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-99]'
        r = curl.http_download(urls=[urln], alpn_proto=proto,
                               extra_args=['--parallel'])
        assert r.exit_code == 0
        r.check_responses(count=100, exp_status=200)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1
        else:
            # http2 parallel transfers will use one connection (common limit is 100)
            assert r.total_connects == 1

    # download 500 files sequential
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_05_download_500_sequential(self, env: Env,
                                           httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-499]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_responses(count=500, exp_status=200)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1
        else:
            # http2 parallel transfers will use one connection (common limit is 100)
            assert r.total_connects == 1

    # download 500 files parallel (default max of 100)
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_06_download_500_parallel(self, env: Env,
                                         httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[000-499]'
        r = curl.http_download(urls=[urln], alpn_proto=proto,
                               extra_args=['--parallel'])
        assert r.exit_code == 0
        r.check_responses(count=500, exp_status=200)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1
        else:
            # http2 parallel transfers will use one connection (common limit is 100)
            assert r.total_connects == 1

    # download 500 files parallel (max of 200), only h2
    @pytest.mark.skip(reason="TODO: we get 101 connections created. PIPEWAIT needs a fix")
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_07_download_500_parallel(self, env: Env,
                                         httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-499]'
        r = curl.http_download(urls=[urln], alpn_proto=proto,
                               with_stats=False, extra_args=[
            '--parallel', '--parallel-max', '200'
        ])
        assert r.exit_code == 0, f'{r}'
        r.check_responses(count=500, exp_status=200)
        # http2 should now use 2 connections, at most 5
        assert r.total_connects <= 5, "h2 should use fewer connections here"

    def check_response(self, r: ExecResult, count: int,
                       exp_status: Optional[int] = None):
        if len(r.responses) != count:
            seen_queries = []
            for idx, resp in enumerate(r.responses):
                assert resp['status'] == 200, f'response #{idx} status: {resp["status"]}'
                if 'rquery' not in resp['header']:
                    log.error(f'response #{idx} missing "rquery": {resp["header"]}')
                seen_queries.append(int(resp['header']['rquery']))
            for i in range(0,count-1):
                if i not in seen_queries:
                    log.error(f'response for query {i} missing')
            if r.with_stats and len(r.stats) == count:
                log.error(f'got all {count} stats, though')
        assert len(r.responses) == count
        if exp_status is not None:
            for idx, x in enumerate(r.responses):
                assert x['status'] == exp_status, \
                    f'response #{idx} unexpectedstatus: {x["status"]}'
        if r.with_stats:
            assert len(r.stats) == count, f'{r}'
