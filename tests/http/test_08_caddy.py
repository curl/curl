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

from testenv import Env, CurlClient, Caddy


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.has_caddy(), reason=f"missing caddy")
@pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
class TestCaddy:

    @pytest.fixture(autouse=True, scope='class')
    def caddy(self, env):
        caddy = Caddy(env=env)
        assert caddy.start()
        yield caddy
        caddy.stop()

    def _make_docs_file(self, docs_dir: str, fname: str, fsize: int):
        fpath = os.path.join(docs_dir, fname)
        data1k = 1024*'x'
        flen = 0
        with open(fpath, 'w') as fd:
            while flen < fsize:
                fd.write(data1k)
                flen += len(data1k)
        return flen

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, caddy):
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data1.data', fsize=1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data5.data', fsize=5*1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data10.data', fsize=10*1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data100.data', fsize=100*1024*1024)

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_01_download_1(self, env: Env, caddy: Caddy, repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{caddy.port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(count=1, http_status=200)

    # download 1MB files sequentially
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_02_download_1mb_sequential(self, env: Env, caddy: Caddy,
                                           repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        count = 50
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{caddy.port}/data1.data?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200, connect_count=1)

    # download 1MB files parallel
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_03_download_1mb_parallel(self, env: Env, caddy: Caddy,
                                         repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        count = 20
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{caddy.port}/data1.data?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        r.check_response(count=count, http_status=200)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1, r.dump_logs()
        else:
            assert r.total_connects == 1, r.dump_logs()

    # download 5MB files sequentially
    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_08_04a_download_10mb_sequential(self, env: Env, caddy: Caddy,
                                           repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        count = 40
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{caddy.port}/data5.data?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200, connect_count=1)

    # download 10MB files sequentially
    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_08_04b_download_10mb_sequential(self, env: Env, caddy: Caddy,
                                           repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        count = 20
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{caddy.port}/data10.data?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200, connect_count=1)

    # download 10MB files parallel
    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    def test_08_05_download_1mb_parallel(self, env: Env, caddy: Caddy,
                                         repeat, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        count = 50
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{caddy.port}/data10.data?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        r.check_response(count=count, http_status=200)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1, r.dump_logs()
        else:
            assert r.total_connects == 1, r.dump_logs()

    # upload data parallel, check that they were echoed
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_08_06_upload_parallel(self, env: Env, caddy, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        # limit since we use a separate connection in h1
        count = 20
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{caddy.port}/data10.data?[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto,
                             extra_args=['--parallel'])
        exp_status = 405 if env.caddy_is_at_least('2.7.0') else 200
        r.check_stats(count=count, http_status=exp_status, exitcode=0)
