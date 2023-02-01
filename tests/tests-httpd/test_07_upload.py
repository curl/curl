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
class TestUpload:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        s90 = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678\n"
        with open(os.path.join(env.gen_dir, "data-100k"), 'w') as f:
            for i in range(1000):
                f.write(f"{i:09d}-{s90}")

    # upload small data, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_01_upload_1_small(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == [data]

    # upload large data, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_02_upload_1_large(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-0]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=1, exp_status=200)
        indata = open(fdata).readlines()
        respdata = open(curl.response_file(0)).readlines()
        assert respdata == indata

    # upload data sequentially, check that they were echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_10_upload_sequential(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=count, exp_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # upload large data sequentially, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_11_upload_seq_large(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        count = 50
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=count, exp_status=200)
        indata = open(fdata).readlines()
        r.check_stats(count=count, exp_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata

    # upload data parallel, check that they were echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_20_upload_parallel(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        data = '0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto,
                             extra_args=['--parallel'])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=count, exp_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == [data]

    # upload large data parallel, check that this is what was echoed
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_07_21_upload_parallel_large(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('quiche'):
            pytest.skip("quiche stalls on parallel, large uploads")
        fdata = os.path.join(env.gen_dir, 'data-100k')
        count = 3
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto,
                             extra_args=['--parallel'])
        assert r.exit_code == 0, f'{r}'
        r.check_stats(count=count, exp_status=200)
        indata = open(fdata).readlines()
        r.check_stats(count=count, exp_status=200)
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata

