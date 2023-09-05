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
import pytest

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestAuth:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)
        httpd.clear_extra_configs()
        httpd.reload()

    # download 1 file, not authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_01_digest_get_noauth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(http_status=401)

    # download 1 file, authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_02_digest_get_auth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        r.check_response(http_status=200)

    # PUT data, authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_03_digest_put_auth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        data='0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        r.check_response(http_status=200)

    # PUT data, digest auth large pw
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_14_04_digest_large_pw(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        data='0123456789'
        password = 'x' * 65535
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '--digest', '--user', f'test:{password}',
            '--trace-config', 'http/2,http/3'
        ])
        # digest does not submit the password, but a hash of it, so all
        # works and, since the pw is not correct, we get a 401
        r.check_response(http_status=401)

    # PUT data, basic auth large pw
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_14_05_basic_large_pw(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('quiche'):
            # See <https://github.com/cloudflare/quiche/issues/1573>
            pytest.skip("quiche has problems with large requests")
        # just large enough that nghttp2 will submit
        password = 'x' * (47 * 1024)
        fdata = os.path.join(env.gen_dir, 'data-10m')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto, extra_args=[
            '--basic', '--user', f'test:{password}',
            '--trace-config', 'http/2,http/3'
        ])
        # but apache denies on length limit
        r.check_response(http_status=431)

    # PUT data, basic auth with very large pw
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_14_06_basic_very_large_pw(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('quiche'):
            # See <https://github.com/cloudflare/quiche/issues/1573>
            pytest.skip("quiche has problems with large requests")
        password = 'x' * (64 * 1024)
        fdata = os.path.join(env.gen_dir, 'data-10m')
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto, extra_args=[
            '--basic', '--user', f'test:{password}'
        ])
        # request was never sent
        r.check_response(exitcode=55, http_status=0)
