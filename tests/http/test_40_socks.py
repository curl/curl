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
from typing import Generator
import pytest

from testenv import Env, CurlClient, Dante


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.has_danted(), reason="missing danted")
class TestSocks:

    @pytest.fixture(scope='class')
    def danted(self, env: Env) -> Generator[Dante, None, None]:
        danted = Dante(env=env)
        assert danted.initial_start()
        yield danted
        danted.stop()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-10m", fsize=10*1024*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)

    @pytest.mark.parametrize("sproto", ['socks4', 'socks5'])
    def test_40_01_socks_http(self, env: Env, sproto, danted: Dante, httpd):
        curl = CurlClient(env=env, socks_args=[
            f'--{sproto}', f'127.0.0.1:{danted.port}'
        ])
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url)
        r.check_response(http_status=200)

    @pytest.mark.parametrize("sproto", ['socks4', 'socks5'])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_40_02_socks_https(self, env: Env, sproto, proto, danted: Dante, httpd):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env, socks_args=[
            f'--{sproto}', f'127.0.0.1:{danted.port}'
        ])
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_get(url=url, alpn_proto=proto)
        if proto == 'h3':
            assert r.exit_code == 3  # unsupported combination
        else:
            r.check_response(http_status=200)

    @pytest.mark.parametrize("sproto", ['socks4', 'socks5'])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_40_03_dl_serial(self, env: Env, httpd, danted, proto, sproto):
        count = 3
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-10m?[0-{count-1}]'
        curl = CurlClient(env=env, socks_args=[
            f'--{sproto}', f'127.0.0.1:{danted.port}'
        ])
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200)

    @pytest.mark.parametrize("sproto", ['socks4', 'socks5'])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_40_04_ul_serial(self, env: Env, httpd, danted, proto, sproto):
        fdata = os.path.join(env.gen_dir, 'data-10m')
        count = 2
        curl = CurlClient(env=env, socks_args=[
            f'--{sproto}', f'127.0.0.1:{danted.port}'
        ])
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto)
        r.check_stats(count=count, http_status=200, exitcode=0)
        indata = open(fdata).readlines()
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata
