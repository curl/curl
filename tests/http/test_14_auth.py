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
from testenv import CurlClient, Env

log = logging.getLogger(__name__)


class TestAuth:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)

    # download 1 file, not authenticated
    @pytest.mark.parametrize("proto", Env.http_protos())
    def test_14_01_digest_get_noauth(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        # server offers Digest, we have no credentials
        r.check_response(http_status=401)
        assert r.stats[0]['http_auth_avail'] == 2, f'{r}'
        assert r.stats[0]['http_auth_used'] == 0, f'{r}'

    # download 1 file, authenticated
    @pytest.mark.skipif(condition=not Env.curl_can_digest_auth, reason='curl built without digest auth')
    @pytest.mark.parametrize("proto", Env.http_protos())
    def test_14_02_digest_get_auth(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        # Digest does one roundtrip, so we learn what auth the server supports
        r.check_response(http_status=200)
        assert r.stats[0]['http_auth_avail'] == 2, f'{r}'
        assert r.stats[0]['http_auth_used'] == 2, f'{r}'

    # PUT data, authenticated
    @pytest.mark.skipif(condition=not Env.curl_can_digest_auth, reason='curl built without digest auth')
    @pytest.mark.parametrize("proto", Env.http_protos())
    def test_14_03_digest_put_auth(self, env: Env, httpd, nghttpx, proto):
        data='0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        r.check_response(http_status=200)
        assert r.stats[0]['http_auth_avail'] == 2, f'{r}'
        assert r.stats[0]['http_auth_used'] == 2, f'{r}'

    # PUT data, digest auth large pw
    @pytest.mark.skipif(condition=not Env.curl_can_digest_auth, reason='curl built without digest auth')
    @pytest.mark.parametrize("proto", Env.http_mplx_protos())
    def test_14_04_digest_large_pw(self, env: Env, httpd, nghttpx, proto):
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
        assert r.stats[0]['http_auth_avail'] == 2, f'{r}'
        assert r.stats[0]['http_auth_used'] == 2, f'{r}'

    # PUT data, basic auth large pw
    @pytest.mark.parametrize("proto", Env.http_mplx_protos())
    def test_14_05_basic_large_pw(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.curl_uses_lib('ngtcp2'):
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
        # but apache either denies on length limit or gives a 400
        # Basic has no rountrip, so do not learn the server's auth methods
        r.check_exit_code(0)
        assert r.stats[0]['http_code'] in [400, 431]
        assert r.stats[0]['http_auth_avail'] == 0, f'{r}'
        assert r.stats[0]['http_auth_used'] == 1, f'{r}'

    # PUT data, basic auth with very large pw
    @pytest.mark.parametrize("proto", Env.http_mplx_protos())
    def test_14_06_basic_very_large_pw(self, env: Env, httpd, nghttpx, proto):
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
        # Depending on protocol, we might have an error sending or
        # the server might shutdown the connection and we see the error
        # on receiving
        # Basic has no rountrip, so do not learn the server's auth methods
        assert r.exit_code in [55, 56, 95], f'{r.dump_logs()}'
        assert r.stats[0]['http_auth_avail'] == 0, f'{r}'
        assert r.stats[0]['http_auth_used'] == 1, f'{r}'
