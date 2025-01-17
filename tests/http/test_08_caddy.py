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
import difflib
import filecmp
import logging
import os
import re
import pytest

from testenv import Env, CurlClient, Caddy, LocalClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.has_caddy(), reason="missing caddy")
@pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
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
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data10k.data', fsize=10*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data1.data', fsize=1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data5.data', fsize=5*1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data10.data', fsize=10*1024*1024)
        self._make_docs_file(docs_dir=caddy.docs_dir, fname='data100.data', fsize=100*1024*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_01_download_1(self, env: Env, caddy: Caddy, proto):
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
    def test_08_02_download_1mb_sequential(self, env: Env, caddy: Caddy, proto):
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
    def test_08_03_download_1mb_parallel(self, env: Env, caddy: Caddy, proto):
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
    def test_08_04a_download_10mb_sequential(self, env: Env, caddy: Caddy, proto):
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
    def test_08_04b_download_10mb_sequential(self, env: Env, caddy: Caddy, proto):
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
    def test_08_05_download_1mb_parallel(self, env: Env, caddy: Caddy, proto):
        if proto == 'h3' and not env.have_h3_curl():
            pytest.skip("h3 not supported in curl")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 itself crashes")
        if proto == 'http/1.1' and env.curl_uses_lib('mbedtls'):
            pytest.skip("mbedtls 3.6.0 fails on 50 connections with: "\
                "ssl_handshake returned: (-0x7F00) SSL - Memory allocation failed")
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

    # post data parallel, check that they were echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_06_post_parallel(self, env: Env, httpd, caddy, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        # limit since we use a separate connection in h1
        count = 20
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.domain2}:{caddy.port}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto,
                             extra_args=['--parallel'])
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # put large file, check that they length were echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_07_put_large(self, env: Env, httpd, caddy, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        # limit since we use a separate connection in h1<
        count = 1
        fdata = os.path.join(env.gen_dir, 'data-10m')
        curl = CurlClient(env=env)
        url = f'https://{env.domain2}:{caddy.port}/curltest/put?id=[0-{count-1}]'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto)
        exp_data = [f'{os.path.getsize(fdata)}']
        r.check_response(count=count, http_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == exp_data

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_08_08_earlydata(self, env: Env, httpd, caddy, proto):
        if not env.curl_uses_lib('gnutls'):
            pytest.skip('TLS earlydata only implemented in GnuTLS')
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        docname = 'data10k.data'
        url = f'https://{env.domain1}:{caddy.port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-e',  # use TLS earlydata
             '-f',  # forbid reuse of connections
             '-r', f'{env.domain1}:{caddy.port}:127.0.0.1',
             '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(caddy.docs_dir, docname)
        self.check_downloads(client, srcfile, count)
        earlydata = {}
        for line in r.trace_lines:
            m = re.match(r'^\[t-(\d+)] EarlyData: (-?\d+)', line)
            if m:
                earlydata[int(m.group(1))] = int(m.group(2))
        assert earlydata[0] == 0, f'{earlydata}'
        if proto == 'h3':
            assert earlydata[1] == 71, f'{earlydata}'
        else:
            # Caddy does not support early data on TCP
            assert earlydata[1] == 0, f'{earlydata}'

    def check_downloads(self, client, srcfile: str, count: int,
                        complete: bool = True):
        for i in range(count):
            dfile = client.download_file(i)
            assert os.path.exists(dfile)
            if complete and not filecmp.cmp(srcfile, dfile, shallow=False):
                diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                    b=open(dfile).readlines(),
                                                    fromfile=srcfile,
                                                    tofile=dfile,
                                                    n=1))
                assert False, f'download {dfile} differs:\n{diff}'
