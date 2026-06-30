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
from testenv import CurlClient, Env

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
class TestReuse:

    # check if HTTP/1.1 handles 'Connection: close' correctly
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_01_h1_conn_close(self, env: Env, httpd, configures_httpd, nghttpx, proto):
        httpd.reset_config()
        httpd.set_extra_config('base', [
            'MaxKeepAliveRequests 1',
        ])
        httpd.reload_if_config_changed()
        count = 100
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200)
        # Server sends `Connection: close` on every 2nd request, requiring
        # a new connection
        delta = 5
        assert (count/2 - delta) < r.total_connects < (count/2 + delta)

    @pytest.mark.skipif(condition=Env.httpd_is_at_least('2.5.0'),
                        reason="httpd 2.5+ handles KeepAlives different")
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_02_h1_conn_timeout(self, env: Env, httpd, configures_httpd, nghttpx, proto):
        httpd.reset_config()
        httpd.set_extra_config('base', [
            'KeepAliveTimeout 1',
        ])
        httpd.reload_if_config_changed()
        count = 5
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--rate', '30/m',
        ])
        r.check_response(count=count, http_status=200)
        # Connections time out on server before we send another request,
        assert r.total_connects == count

    # After a partial/aborted HTTP/1.1 response the connection must not be
    # reused (multi_conn_should_close with premature on non-multiplexed conn).
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_03_no_reuse_after_partial(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        auth = env.authority_for(env.domain1, proto)
        # Server promises more bytes than it sends, then resets.
        partial = f'https://{auth}/curltest/tweak?id=0&chunks=1&chunk_size=100&body_error=reset'
        ok = f'https://{auth}/data.json'
        r = curl.http_download(urls=[partial, ok], alpn_proto=proto, extra_args=[
            '--retry', '0',
        ])
        # First transfer fails (partial/reset); second succeeds on a new connection.
        assert len(r.stats) == 2, r.dump_logs()
        assert r.stats[0]['exitcode'] != 0, r.dump_logs()
        assert r.stats[1].get('http_code') == 200, r.dump_logs()
        # Both transfers must open their own connection.
        assert r.stats[0]['num_connects'] == 1, r.dump_logs()
        assert r.stats[1]['num_connects'] == 1, r.dump_logs()
        assert r.total_connects == 2, r.dump_logs()

    # HTTP uses PROTOPT_CREDSPERREQUEST: Basic credentials are per request, so
    # different -u values still reuse the idle connection (unlike NTLM/Negotiate
    # which bind credentials onto the connection).
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_04_reuse_different_basic_credentials(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json?cred=1'
        url2 = f'https://{env.authority_for(env.domain1, proto)}/data.json?cred=2'
        r = curl.http_download(urls=[url1, url2], alpn_proto=proto, url_options={
            url1: ['-u', 'user1:password1'],
            url2: ['-u', 'user2:password2'],
        })
        assert len(r.stats) == 2, r.dump_logs()
        assert r.stats[0].get('http_code') == 200, r.dump_logs()
        assert r.stats[1].get('http_code') == 200, r.dump_logs()
        assert r.stats[0]['num_connects'] == 1, r.dump_logs()
        assert r.stats[1]['num_connects'] == 0, r.dump_logs()
        assert r.total_connects == 1, r.dump_logs()

    # Different target hostnames must not reuse even if they resolve to the
    # same address (Curl_peer_same_destination matches hostname + port).
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_05_no_reuse_different_host(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        # domain1 and domain2 are both served by the same httpd instance.
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        url2 = f'https://{env.authority_for(env.domain2, proto)}/data.json'
        r = curl.http_download(urls=[url1, url2], alpn_proto=proto)
        r.check_response(count=2, http_status=200)
        assert r.stats[0]['num_connects'] == 1, r.dump_logs()
        assert r.stats[1]['num_connects'] == 1, r.dump_logs()
        assert r.total_connects == 2, r.dump_logs()

    # Positive control: same host reuses one connection.
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_06_reuse_same_host(self, env: Env, httpd, nghttpx, proto):
        curl = CurlClient(env=env)
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json?a=1'
        url2 = f'https://{env.authority_for(env.domain1, proto)}/data.json?a=2'
        r = curl.http_download(urls=[url1, url2], alpn_proto=proto)
        assert len(r.stats) == 2, r.dump_logs()
        assert r.stats[0].get('http_code') == 200, r.dump_logs()
        assert r.stats[1].get('http_code') == 200, r.dump_logs()
        assert r.stats[0]['num_connects'] == 1, r.dump_logs()
        assert r.stats[1]['num_connects'] == 0, r.dump_logs()
        assert r.total_connects == 1, r.dump_logs()
