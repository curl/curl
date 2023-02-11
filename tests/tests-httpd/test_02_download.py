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
import os
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestDownload:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()

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
    def _class_scope(self, env, httpd):
        self._make_docs_file(docs_dir=httpd.docs_dir, fname='data1.data', fsize=1024*1024)
        self._make_docs_file(docs_dir=httpd.docs_dir, fname='data10.data', fsize=10*1024*1024)
        self._make_docs_file(docs_dir=httpd.docs_dir, fname='data100.data', fsize=100*1024*1024)

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_01_download_1(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)

    # download 2 files
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_02_download_2(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_stats(count=2, exp_status=200)

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
        r.check_stats(count=100, exp_status=200)
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
        r.check_stats(count=100, exp_status=200)
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
        r.check_stats(count=500, exp_status=200)
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
        r.check_stats(count=500, exp_status=200)
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
        r.check_stats(count=500, exp_status=200)
        # http2 should now use 2 connections, at most 5
        assert r.total_connects <= 5, "h2 should use fewer connections here"

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_08_1MB_serial(self, env: Env,
                              httpd, nghttpx, repeat, proto):
        count = 20
        urln = f'https://{env.authority_for(env.domain1, proto)}/data1.data?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_09_1MB_parallel(self, env: Env,
                              httpd, nghttpx, repeat, proto):
        count = 20
        urln = f'https://{env.authority_for(env.domain1, proto)}/data1.data?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_10_10MB_serial(self, env: Env,
                              httpd, nghttpx, repeat, proto):
        count = 20
        urln = f'https://{env.authority_for(env.domain1, proto)}/data10.data?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_11_10MB_parallel(self, env: Env,
                              httpd, nghttpx, repeat, proto):
        count = 20
        urln = f'https://{env.authority_for(env.domain1, proto)}/data10.data?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)
