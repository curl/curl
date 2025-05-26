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
import sys
import pytest
from typing import List, Union

from testenv import Env, CurlClient, LocalClient, ExecResult


log = logging.getLogger(__name__)


class TestUpload:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        env.make_data_file(indir=env.gen_dir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-63k", fsize=63*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-64k", fsize=64*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-1m+", fsize=(1024*1024)+1)
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)

    # upload small data, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_01_upload_1_small(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto)
        r.check_stats(count=1, http_status=200, exitcode=0)
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == [data]

    # upload large data, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_02_upload_1_large(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        r.check_stats(count=1, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    # upload data sequentially, check that they were echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_10_upload_sequential(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        count = 20
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto)
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # upload data parallel, check that they were echoed
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_07_11_upload_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        # limit since we use a separate connection in h1
        count = 20
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto,
                             extra_args=['--parallel'])
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # upload large data sequentially, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_12_upload_seq_large(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        count = 10
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        r.check_response(count=count, http_status=200)
        indata = open(fdata).readlines()
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata

    # upload very large data sequentially, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_13_upload_seq_large(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 2
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        r.check_stats(count=count, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata

    # upload from stdin, issue #14870
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    @pytest.mark.parametrize("indata", [
        '', '1', '123\n456andsomething\n\n'
    ])
    def test_07_14_upload_stdin(self, env: Env, httpd, nghttpx, proto, indata):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-{count-1}]'
        r = curl.http_put(urls=[url], data=indata, alpn_proto=proto)
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [f'{len(indata)}']

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_15_hx_put(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        upload_size = 128*1024
        url = f'https://localhost:{env.https_port}/curltest/put'
        client = LocalClient(name='hx-upload', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-S', f'{upload_size}', '-V', proto, url
        ])
        r.check_exit_code(0)
        self.check_downloads(client, r, [f"{upload_size}"], count)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_16_hx_put_reuse(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        upload_size = 128*1024
        url = f'https://localhost:{env.https_port}/curltest/put'
        client = LocalClient(name='hx-upload', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-S', f'{upload_size}', '-R', '-V', proto, url
        ])
        r.check_exit_code(0)
        self.check_downloads(client, r, [f"{upload_size}"], count)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_17_hx_post_reuse(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        upload_size = 128*1024
        url = f'https://localhost:{env.https_port}/curltest/echo'
        client = LocalClient(name='hx-upload', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-M', 'POST', '-S', f'{upload_size}', '-R', '-V', proto, url
        ])
        r.check_exit_code(0)
        self.check_downloads(client, r, ["x" * upload_size], count)

    # upload data parallel, check that they were echoed
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_07_20_upload_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        # limit since we use a separate connection in h1
        count = 10
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto,
                             extra_args=['--parallel'])
        r.check_stats(count=count, http_status=200, exitcode=0)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # upload large data parallel, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_07_21_upload_parallel_large(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        # limit since we use a separate connection in h1
        count = 10
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto,
                             extra_args=['--parallel'])
        r.check_response(count=count, http_status=200)
        self.check_download(r, count, fdata, curl)

    # upload large data parallel to a URL that denies uploads
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_07_22_upload_parallel_fail(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 20
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}'\
            f'/curltest/tweak?status=400&delay=5ms&chunks=1&body_error=reset&id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto,
                             extra_args=['--parallel'])
        # depending on timing and protocol, we might get CURLE_PARTIAL_FILE or
        # CURLE_SEND_ERROR or CURLE_HTTP3 or CURLE_HTTP2_STREAM
        r.check_stats(count=count, exitcode=[18, 55, 92, 95])

    # PUT 100k
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_30_put_100k(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-{count-1}]'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto,
                          extra_args=['--parallel'])
        r.check_stats(count=count, http_status=200, exitcode=0)
        exp_data = [f'{os.path.getsize(fdata)}']
        r.check_response(count=count, http_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == exp_data

    # PUT 10m
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_31_put_10m(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-{count-1}]&chunk_delay=2ms'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto,
                          extra_args=['--parallel'])
        r.check_stats(count=count, http_status=200, exitcode=0)
        exp_data = [f'{os.path.getsize(fdata)}']
        r.check_response(count=count, http_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == exp_data

    # issue #10591
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_32_issue_10591(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-{count-1}]'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto)
        r.check_stats(count=count, http_status=200, exitcode=0)

    # issue #11157, upload that is 404'ed by server, needs to terminate
    # correctly and not time out on sending
    def test_07_33_issue_11157a(self, env: Env, httpd, nghttpx):
        proto = 'h2'
        fdata = os.path.join(env.gen_dir, 'data-10m')
        # send a POST to our PUT handler which will send immediately a 404 back
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put'
        curl = CurlClient(env=env)
        r = curl.run_direct(with_stats=True, args=[
            '--resolve', f'{env.authority_for(env.domain1, proto)}:127.0.0.1',
            '--cacert', env.ca.cert_file,
            '--request', 'POST',
            '--max-time', '5', '-v',
            '--url', url,
            '--form', 'idList=12345678',
            '--form', 'pos=top',
            '--form', 'name=mr_test',
            '--form', f'fileSource=@{fdata};type=application/pdf',
        ])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(1, 404)

    # issue #11157, send upload that is slowly read in
    def test_07_33_issue_11157b(self, env: Env, httpd, nghttpx):
        proto = 'h2'
        fdata = os.path.join(env.gen_dir, 'data-10m')
        # tell our test PUT handler to read the upload more slowly, so
        # that the send buffering and transfer loop needs to wait
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?chunk_delay=2ms'
        curl = CurlClient(env=env)
        r = curl.run_direct(with_stats=True, args=[
            '--verbose', '--trace-config', 'ids,time',
            '--resolve', f'{env.authority_for(env.domain1, proto)}:127.0.0.1',
            '--cacert', env.ca.cert_file,
            '--request', 'PUT',
            '--max-time', '10', '-v',
            '--url', url,
            '--form', 'idList=12345678',
            '--form', 'pos=top',
            '--form', 'name=mr_test',
            '--form', f'fileSource=@{fdata};type=application/pdf',
        ])
        assert r.exit_code == 0, r.dump_logs()
        r.check_stats(1, 200)

    def test_07_34_issue_11194(self, env: Env, httpd, nghttpx):
        proto = 'h2'
        # tell our test PUT handler to read the upload more slowly, so
        # that the send buffering and transfer loop needs to wait
        fdata = os.path.join(env.gen_dir, 'data-100k')
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put'
        curl = CurlClient(env=env)
        r = curl.run_direct(with_stats=True, args=[
            '--verbose', '--trace-config', 'ids,time',
            '--resolve', f'{env.authority_for(env.domain1, proto)}:127.0.0.1',
            '--cacert', env.ca.cert_file,
            '--request', 'PUT',
            '--digest', '--user', 'test:test',
            '--data-binary', f'@{fdata}',
            '--url', url,
        ])
        assert r.exit_code == 0, r.dump_logs()
        r.check_stats(1, 200)

    # upload large data on a h1 to h2 upgrade
    def test_07_35_h1_h2_upgrade_upload(self, env: Env, httpd, nghttpx):
        fdata = os.path.join(env.gen_dir, 'data-100k')
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', extra_args=[
            '--http2'
        ])
        r.check_response(count=1, http_status=200)
        # apache does not Upgrade on request with a body
        assert r.stats[0]['http_version'] == '1.1', f'{r}'
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    # upload to a 301,302,303 response
    @pytest.mark.parametrize("redir", ['301', '302', '303'])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_36_upload_30x(self, env: Env, httpd, nghttpx, redir, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        data = '0123456789' * 10
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo{redir}?id=[0-0]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '-L', '--trace-config', 'http/2,http/3'
        ])
        r.check_response(count=1, http_status=200)
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == []  # was transformed to a GET

    # upload to a 307 response
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_37_upload_307(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        data = '0123456789' * 10
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo307?id=[0-0]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '-L', '--trace-config', 'http/2,http/3'
        ])
        r.check_response(count=1, http_status=200)
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == [data]  # was POST again

    # POST form data, yet another code path in transfer
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_38_form_small(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_form(urls=[url], alpn_proto=proto, form={
            'name1': 'value1',
        })
        r.check_stats(count=1, http_status=200, exitcode=0)

    # POST data urlencoded, small enough to be sent with request headers
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_39_post_urlenc_small(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-63k')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto, extra_args=[
            '--trace-config', 'http/2,http/3'
        ])
        r.check_stats(count=1, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    # POST data urlencoded, large enough to be sent separate from request headers
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_40_post_urlenc_large(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-64k')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto, extra_args=[
            '--trace-config', 'http/2,http/3'
        ])
        r.check_stats(count=1, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    # POST data urlencoded, small enough to be sent with request headers
    # and request headers are so large that the first send is larger
    # than our default upload buffer length (64KB).
    # Unfixed, this will fail when run with CURL_DBG_SOCK_WBLOCK=80 most
    # of the time
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_41_post_urlenc_small(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        if proto == 'h3' and env.curl_uses_lib('quiche'):
            pytest.skip("quiche has CWND issues with large requests")
        fdata = os.path.join(env.gen_dir, 'data-63k')
        curl = CurlClient(env=env)
        extra_args = ['--trace-config', 'http/2,http/3']
        # add enough headers so that the first send chunk is > 64KB
        for i in range(63):
            extra_args.extend(['-H', f'x{i:02d}: {"y"*1019}'])
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto, extra_args=extra_args)
        r.check_stats(count=1, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    def check_download(self, r: ExecResult, count: int, srcfile: Union[str, os.PathLike], curl: CurlClient):
        for i in range(count):
            dfile = curl.download_file(i)
            assert os.path.exists(dfile), f'download {dfile} missing\n{r.dump_logs()}'
            if not filecmp.cmp(srcfile, dfile, shallow=False):
                diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                    b=open(dfile).readlines(),
                                                    fromfile=srcfile,
                                                    tofile=dfile,
                                                    n=1))
                assert False, f'download {dfile} differs:\n{diff}\n{r.dump_logs()}'

    # upload data, pause, let connection die with an incomplete response
    # issues #11769 #13260
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_42a_upload_disconnect(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        client = LocalClient(name='upload-pausing', env=env, timeout=60)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]&die_after=0'
        r = client.run(['-V', proto, url])
        if r.exit_code == 18:  # PARTIAL_FILE is always ok
            pass
        elif proto == 'h2':
            # CURLE_HTTP2, CURLE_HTTP2_STREAM
            assert r.exit_code in [16, 92], f'unexpected exit code\n{r.dump_logs()}'
        elif proto == 'h3':
            r.check_exit_code(95)  # CURLE_HTTP3 also ok
        else:
            r.check_exit_code(18)  # will fail as it should

    # upload data, pause, let connection die without any response at all
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_42b_upload_disconnect(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        client = LocalClient(name='upload-pausing', env=env, timeout=60)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=0&just_die=1'
        r = client.run(['-V', proto, url])
        exp_code = 52  # GOT_NOTHING
        if proto == 'h2' or proto == 'h3':
            exp_code = 0  # we get a 500 from the server
        r.check_exit_code(exp_code)  # GOT_NOTHING

    # upload data, pause, let connection die after 100 continue
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_42c_upload_disconnect(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        client = LocalClient(name='upload-pausing', env=env, timeout=60)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=0&die_after_100=1'
        r = client.run(['-V', proto, url])
        exp_code = 52  # GOT_NOTHING
        if proto == 'h2' or proto == 'h3':
            exp_code = 0  # we get a 500 from the server
        r.check_exit_code(exp_code)  # GOT_NOTHING

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_43_upload_denied(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_ossl_quic():
            pytest.skip("openssl-quic is flaky in filed PUTs")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 fails here")
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 1
        max_upload = 128 * 1024
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?'\
            f'id=[0-{count-1}]&max_upload={max_upload}'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto,
                          extra_args=['--trace-config', 'all'])
        r.check_stats(count=count, http_status=413, exitcode=0)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    @pytest.mark.parametrize("httpcode", [301, 302, 307, 308])
    def test_07_44_put_redir(self, env: Env, httpd, nghttpx, proto, httpcode):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        upload_size = 128*1024
        url = f'https://localhost:{env.https_port}/curltest/put-redir-{httpcode}'
        client = LocalClient(name='hx-upload', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-l', '-S', f'{upload_size}', '-V', proto, url
        ])
        r.check_exit_code(0)
        results = [int(m.group(1)) for line in r.trace_lines
                     if (m := re.match(r'.* FINISHED, result=(\d+), response=(\d+)', line))]
        httpcodes = [int(m.group(2)) for line in r.trace_lines
                     if (m := re.match(r'.* FINISHED, result=(\d+), response=(\d+)', line))]
        if httpcode == 308:
            assert results[0] == 65, f'{r}'  # could not rewind input
        else:
            assert httpcodes[0] == httpcode, f'{r}'

    # speed limited on put handler
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_50_put_speed_limit(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        fdata = os.path.join(env.gen_dir, 'data-100k')
        up_len = 100 * 1024
        speed_limit = 50 * 1024
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-0]'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto,
                          with_headers=True, extra_args=[
            '--limit-rate', f'{speed_limit}'
        ])
        r.check_response(count=count, http_status=200)
        assert r.responses[0]['header']['received-length'] == f'{up_len}', f'{r.responses[0]}'
        up_speed = r.stats[0]['speed_upload']
        assert (speed_limit * 0.5) <= up_speed <= (speed_limit * 1.5), f'{r.stats[0]}'

    # speed limited on echo handler
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_51_echo_speed_limit(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        fdata = os.path.join(env.gen_dir, 'data-100k')
        speed_limit = 50 * 1024
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto,
                             with_headers=True, extra_args=[
            '--limit-rate', f'{speed_limit}'
        ])
        r.check_response(count=count, http_status=200)
        up_speed = r.stats[0]['speed_upload']
        assert (speed_limit * 0.5) <= up_speed <= (speed_limit * 1.5), f'{r.stats[0]}'

    # upload larger data, triggering "Expect: 100-continue" code paths
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_07_60_upload_exp100(self, env: Env, httpd, nghttpx, proto):
        fdata = os.path.join(env.gen_dir, 'data-1m+')
        read_delay = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-0]'\
            f'&read_delay={read_delay}s'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto, extra_args=[
            '--expect100-timeout', f'{read_delay+1}'
        ])
        r.check_stats(count=1, http_status=200, exitcode=0)

    # upload larger data, triggering "Expect: 100-continue" code paths
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_07_61_upload_exp100_timeout(self, env: Env, httpd, nghttpx, proto):
        fdata = os.path.join(env.gen_dir, 'data-1m+')
        read_delay = 2
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/put?id=[0-0]'\
            f'&read_delay={read_delay}s'
        r = curl.http_put(urls=[url], fdata=fdata, alpn_proto=proto, extra_args=[
            '--expect100-timeout', f'{read_delay-1}'
        ])
        r.check_stats(count=1, http_status=200, exitcode=0)

    # issue #15688 when posting a form and cr_mime_read() is called with
    # length < 4, we did not progress
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_07_62_upload_issue_15688(self, env: Env, httpd, proto):
        # this length leads to (including multipart formatting) to a
        # client reader invocation with length 1.
        upload_len = 196169
        fname = f'data-{upload_len}'
        env.make_data_file(indir=env.gen_dir, fname=fname, fsize=upload_len)
        fdata = os.path.join(env.gen_dir, fname)
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_form(urls=[url], form={
            'file': f'@{fdata}',
        }, alpn_proto=proto, extra_args=[
            '--max-time', '10'
        ])
        r.check_stats(count=1, http_status=200, exitcode=0)

    # nghttpx is the only server we have that supports TLS early data and
    # has a limit of 16k it announces
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx")
    @pytest.mark.parametrize("proto,upload_size,exp_early", [
        pytest.param('http/1.1', 100, 203, id='h1-small-body'),
        pytest.param('http/1.1', 10*1024, 10345, id='h1-medium-body'),
        pytest.param('http/1.1', 32*1024, 16384, id='h1-limited-body'),
        pytest.param('h2', 10*1024, 10378, id='h2-medium-body'),
        pytest.param('h2', 32*1024, 16384, id='h2-limited-body'),
        pytest.param('h3', 1024, 1126, id='h3-small-body'),
        pytest.param('h3', 1024 * 1024, 131177, id='h3-limited-body'),
        # h3: limited+body (long app data). The 0RTT size is limited by
        # our sendbuf size of 128K.
    ])
    def test_07_70_put_earlydata(self, env: Env, httpd, nghttpx, proto, upload_size, exp_early):
        if not env.curl_can_early_data():
            pytest.skip('TLS earlydata not implemented')
        if proto == 'h3' and \
           (not env.have_h3() or not env.curl_can_h3_early_data()):
            pytest.skip("h3 not supported")
        if proto != 'h3' and sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('failing on macOS CI runners')
        count = 2
        # we want this test to always connect to nghttpx, since it is
        # the only server we have that supports TLS earlydata
        port = env.port_for(proto)
        if proto != 'h3':
            port = env.nghttpx_https_port
        url = f'https://{env.domain1}:{port}/curltest/put'
        client = LocalClient(name='hx-upload', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-e',  # use TLS earlydata
             '-f',  # forbid reuse of connections
             '-l',  # announce upload length, no 'Expect: 100'
             '-S', f'{upload_size}',
             '-r', f'{env.domain1}:{port}:127.0.0.1',
             '-V', proto, url
        ])
        r.check_exit_code(0)
        self.check_downloads(client, r, [f"{upload_size}"], count)
        earlydata = {}
        for line in r.trace_lines:
            m = re.match(r'^\[t-(\d+)] EarlyData: (-?\d+)', line)
            if m:
                earlydata[int(m.group(1))] = int(m.group(2))
        assert earlydata[0] == 0, f'{earlydata}\n{r.dump_logs()}'
        # depending on cpu load, curl might not upload as much before
        # the handshake starts and early data stops.
        assert 102 <= earlydata[1] <= exp_early, f'{earlydata}\n{r.dump_logs()}'

    def check_downloads(self, client, r, source: List[str], count: int,
                        complete: bool = True):
        for i in range(count):
            dfile = client.download_file(i)
            assert os.path.exists(dfile), f'download {dfile} missing\n{r.dump_logs()}'
            if complete:
                diff = "".join(difflib.unified_diff(a=source,
                                                    b=open(dfile).readlines(),
                                                    fromfile='-',
                                                    tofile=dfile,
                                                    n=1))
                assert not diff, f'download {dfile} differs:\n{diff}\n{r.dump_logs()}'
