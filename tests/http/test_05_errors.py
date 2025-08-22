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

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.55'),
                    reason=f"httpd version too old for this: {Env.httpd_version()}")
class TestErrors:

    # download 1 file, check that we get CURLE_PARTIAL_FILE
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_05_01_partial_1(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
            f'/curltest/tweak?id=[0-{count - 1}]'\
            '&chunks=3&chunk_size=16000&body_error=reset'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--retry', '0'
        ])
        r.check_exit_code(False)
        invalid_stats = []
        for idx, s in enumerate(r.stats):
            if 'exitcode' not in s or s['exitcode'] not in [18, 56, 92, 95]:
                invalid_stats.append(f'request {idx} exit with {s["exitcode"]}')
        assert len(invalid_stats) == 0, f'failed: {invalid_stats}'

    # download files, check that we get CURLE_PARTIAL_FILE for all
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_05_02_partial_20(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_ossl_quic():
            pytest.skip("openssl-quic is flaky in yielding proper error codes")
        count = 20
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
            f'/curltest/tweak?id=[0-{count - 1}]'\
            '&chunks=5&chunk_size=16000&body_error=reset'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--retry', '0', '--parallel',
        ])
        r.check_exit_code(False)
        assert len(r.stats) == count, f'did not get all stats: {r}'
        invalid_stats = []
        for idx, s in enumerate(r.stats):
            if 'exitcode' not in s or s['exitcode'] not in [18, 55, 56, 92, 95]:
                invalid_stats.append(f'request {idx} exit with {s["exitcode"]}\n{s}')
        assert len(invalid_stats) == 0, f'failed: {invalid_stats}'

    # access a resource that, on h2, RST the stream with HTTP_1_1_REQUIRED
    def test_05_03_required(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        proto = 'http/1.1'
        urln = f'https://{env.authority_for(env.domain1, proto)}/curltest/1_1'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_exit_code(0)
        r.check_response(http_status=200, count=1)
        proto = 'h2'
        urln = f'https://{env.authority_for(env.domain1, proto)}/curltest/1_1'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_exit_code(0)
        r.check_response(http_status=200, count=1)
        # check that we did a downgrade
        assert r.stats[0]['http_version'] == '1.1', r.dump_logs()

    # On the URL used here, Apache is doing an "unclean" TLS shutdown,
    # meaning it sends no shutdown notice and just closes TCP.
    # The HTTP response delivers a body without Content-Length. We expect:
    # - http/1.0 to fail since it relies on a clean connection close to
    #   detect the end of the body
    # - http/1.1 to work since it will used "chunked" transfer encoding
    #   and stop receiving when that signals the end
    # - h2 to work since it will signal the end of the response before
    #   and not see the "unclean" close either
    @pytest.mark.parametrize("proto", ['http/1.0', 'http/1.1', 'h2'])
    def test_05_04_unclean_tls_shutdown(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 10 if proto == 'h2' else 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}'\
            f'/curltest/shutdown_unclean?id=[0-{count-1}]&chunks=4'
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--parallel', '--trace-config', 'ssl'
        ])
        if proto == 'http/1.0':
            # we are inconsistent if we fail or not in missing TLS shutdown
            # openssl code ignore such errors intentionally in non-debug builds
            r.check_exit_code(56)
        else:
            r.check_exit_code(0)
            r.check_response(http_status=200, count=count)
