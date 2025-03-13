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
import pytest

from testenv import Env
from testenv import CurlClient


log = logging.getLogger(__name__)


class TestBasic:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    # simple http: GET
    def test_01_01_http_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url)
        r.check_response(http_status=200)
        assert r.json['server'] == env.domain1

    # simple https: GET, any http version
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    def test_01_02_https_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_get(url=url)
        r.check_response(http_status=200)
        assert r.json['server'] == env.domain1

    # simple https: GET, h2 wanted and got
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    def test_01_03_h2_get(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2'])
        r.check_response(http_status=200, protocol='HTTP/2')
        assert r.json['server'] == env.domain1

    # simple https: GET, h2 unsupported, fallback to h1
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    def test_01_04_h2_unsupported(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.domain2}:{env.https_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2'])
        r.check_response(http_status=200, protocol='HTTP/1.1')
        assert r.json['server'] == env.domain2

    # simple h3: GET, want h3 and get it
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_01_05_h3_get(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.h3_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http3-only'])
        r.check_response(http_status=200, protocol='HTTP/3')
        assert r.json['server'] == env.domain1

    # simple download, check connect/handshake timings
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_01_06_timings(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True)
        r.check_stats(http_status=200, count=1,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')
        assert r.stats[0]['time_connect'] > 0, f'{r.stats[0]}'
        assert r.stats[0]['time_appconnect'] > 0, f'{r.stats[0]}'

    # simple https: HEAD
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    def test_01_07_head(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, with_headers=True,
                               extra_args=['-I'])
        r.check_stats(http_status=200, count=1, exitcode=0,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')
        # got the Conten-Length: header, but did not download anything
        assert r.responses[0]['header']['content-length'] == '30', f'{r.responses[0]}'
        assert r.stats[0]['size_download'] == 0, f'{r.stats[0]}'

    # http: GET for HTTP/2, see Upgrade:, 101 switch
    def test_01_08_h2_upgrade(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2'])
        r.check_exit_code(0)
        assert len(r.responses) == 2, f'{r.responses}'
        assert r.responses[0]['status'] == 101, f'{r.responses[0]}'
        assert r.responses[1]['status'] == 200, f'{r.responses[1]}'
        assert r.responses[1]['protocol'] == 'HTTP/2', f'{r.responses[1]}'
        assert r.json['server'] == env.domain1

    # http: GET for HTTP/2 with prior knowledge
    def test_01_09_h2_prior_knowledge(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2-prior-knowledge'])
        r.check_exit_code(0)
        assert len(r.responses) == 1, f'{r.responses}'
        assert r.response['status'] == 200, f'{r.responsw}'
        assert r.response['protocol'] == 'HTTP/2', f'{r.response}'
        assert r.json['server'] == env.domain1

    # http: strip TE header in HTTP/2 requests
    def test_01_10_te_strip(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_get(url=url, extra_args=['--http2', '-H', 'TE: gzip'])
        r.check_exit_code(0)
        assert len(r.responses) == 1, f'{r.responses}'
        assert r.responses[0]['status'] == 200, f'{r.responses[1]}'
        assert r.responses[0]['protocol'] == 'HTTP/2', f'{r.responses[1]}'

    # http: large response headers
    # send 48KB+ sized response headers to check we handle that correctly
    # larger than 64KB headers expose a bug in Apache HTTP/2 that is not
    # RSTing the stream correclty when its internal limits are exceeded.
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_01_11_large_resp_headers(self, env: Env, httpd, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}' \
              f'/curltest/tweak?x-hd={48 * 1024}'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[])
        r.check_exit_code(0)
        assert len(r.responses) == 1, f'{r.responses}'
        assert r.responses[0]['status'] == 200, f'{r.responses}'

    # http: response headers larger than what curl buffers for
    @pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.64'),
                        reason='httpd must be at least 2.4.64')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_01_12_xlarge_resp_headers(self, env: Env, httpd, proto):
        httpd.set_extra_config('base', [
            f'H2MaxHeaderBlockLen {130 * 1024}',
        ])
        httpd.reload()
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}' \
              f'/curltest/tweak?x-hd={128 * 1024}'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[])
        r.check_exit_code(0)
        assert len(r.responses) == 1, f'{r.responses}'
        assert r.responses[0]['status'] == 200, f'{r.responses}'

    # http: 1 response header larger than what curl buffers for
    @pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.64'),
                        reason='httpd must be at least 2.4.64')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_01_13_megalarge_resp_headers(self, env: Env, httpd, proto):
        httpd.set_extra_config('base', [
            'LogLevel http2:trace2',
            f'H2MaxHeaderBlockLen {130 * 1024}',
        ])
        httpd.reload()
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}' \
              f'/curltest/tweak?x-hd1={128 * 1024}'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[])
        if proto == 'h2':
            r.check_exit_code(16)  # CURLE_HTTP2
        else:
            r.check_exit_code(100)  # CURLE_TOO_LARGE

    # http: several response headers, together > 256 KB
    # nghttp2 error -905: Too many CONTINUATION frames following a HEADER frame
    @pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.64'),
                        reason='httpd must be at least 2.4.64')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_01_14_gigalarge_resp_headers(self, env: Env, httpd, proto):
        httpd.set_extra_config('base', [
            'LogLevel http2:trace2',
            f'H2MaxHeaderBlockLen {1024 * 1024}',
        ])
        httpd.reload()
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}' \
              f'/curltest/tweak?x-hd={256 * 1024}'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[])
        if proto == 'h2':
            r.check_exit_code(16)  # CURLE_HTTP2
        else:
            r.check_exit_code(0)   # 1.1 can do

    # http: one response header > 256 KB
    @pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.64'),
                        reason='httpd must be at least 2.4.64')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_01_15_gigalarge_resp_headers(self, env: Env, httpd, proto):
        httpd.set_extra_config('base', [
            'LogLevel http2:trace2',
            f'H2MaxHeaderBlockLen {1024 * 1024}',
        ])
        httpd.reload()
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}' \
              f'/curltest/tweak?x-hd1={256 * 1024}'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[])
        if proto == 'h2':
            r.check_exit_code(16)  # CURLE_HTTP2
        else:
            r.check_exit_code(100)  # CURLE_TOO_LARGE
