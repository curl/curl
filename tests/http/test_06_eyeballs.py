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
import re
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


class TestEyeballs:

    # download using only HTTP/3 on working server
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_01_h3_only(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '3'

    # download using only HTTP/3 on missing server
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_02_h3_only(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{env.https_only_tcp_port}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3-only'])
        r.check_response(exitcode=7, http_status=None)

    # download using HTTP/3 on missing server with fallback on h2
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_03_h3_fallback_h2(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{env.https_only_tcp_port}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '2'

    # download using HTTP/3 on missing server with fallback on http/1.1
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_04_h3_fallback_h1(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.domain2}:{env.https_only_tcp_port}/data.json'
        r = curl.http_download(urls=[urln], extra_args=['--http3'])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '1.1'

    # make a successful https: transfer and observer the timer stats
    def test_06_10_stats_success(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[urln])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['time_connect'] > 0.0
        assert r.stats[0]['time_appconnect'] > 0.0

    # make https: to a hostname that tcp connects, but will not verify
    def test_06_11_stats_fail_verify(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://not-valid.com:{env.https_port}/data.json'
        r = curl.http_download(urls=[urln], extra_args=[
            '--resolve', f'not-valid.com:{env.https_port}:127.0.0.1'
        ])
        r.check_response(count=1, http_status=0, exitcode=False)
        assert r.stats[0]['time_connect'] > 0.0    # was tcp connected
        assert r.stats[0]['time_appconnect'] == 0  # but not SSL verified

    # make https: to an invalid address
    def test_06_12_stats_fail_tcp(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = 'https://not-valid.com:1/data.json'
        r = curl.http_download(urls=[urln], extra_args=[
            '--resolve', f'not-valid.com:{1}:127.0.0.1'
        ])
        r.check_response(count=1, http_status=None, exitcode=False)
        assert r.stats[0]['time_connect'] == 0     # no one should have listened
        assert r.stats[0]['time_appconnect'] == 0  # did not happen either

    # check timers when trying 3 unresponsive addresses
    @pytest.mark.skipif(condition=not Env.curl_has_feature('IPv6'),
                        reason='curl lacks ipv6 support')
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason="needs curl verbose strings")
    def test_06_13_timers(self, env: Env):
        curl = CurlClient(env=env)
        # ipv6 0100::/64 is supposed to go into the void (rfc6666)
        r = curl.http_download(urls=['https://xxx.invalid/'], extra_args=[
            '--resolve', 'xxx.invalid:443:0100::1,0100::2,0100::3',
            '--connect-timeout', '1',
            '--happy-eyeballs-timeout-ms', '123',
            '--trace-config', 'timer,happy-eyeballs,tcp'
        ])
        r.check_response(count=1, http_status=None, exitcode=False)
        assert r.stats[0]['time_connect'] == 0     # no one connected
        # check that we indeed started attempts on all 3 addresses
        tcp_attempts = [line for line in r.trace_lines
                         if re.match(r'.*Trying \[100::[123]]:443', line)]
        assert len(tcp_attempts) == 3, f'fond: {"".join(tcp_attempts)}\n{r.dump_logs()}'
        # if the 0100::/64 really goes into the void, we should see 2 HAPPY_EYEBALLS
        # timeouts being set here
        failed_attempts = [line for line in r.trace_lines
                           if re.match(r'.*checked connect attempts: 0 ongoing', line)]
        if len(failed_attempts):
            # github CI fails right away with "Network is unreachable", slackers...
            assert len(failed_attempts) == 3, f'found: {"".join(failed_attempts)}\n{r.dump_logs()}'
        else:
            # no immediately failed attempts, as should be
            he_timers_set = [line for line in r.trace_lines
                             if re.match(r'.*\[TIMER] \[HAPPY_EYEBALLS] set for', line)]
            assert len(he_timers_set) == 2, f'found: {"".join(he_timers_set)}\n{r.dump_logs()}'

    # download using HTTP/3 on missing server with alt-svc pointing there
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_20_h2_altsvc_h3_fallback(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{env.https_only_tcp_port}/data.json'
        altsvc_file = curl.mk_altsvc_file('test_06',
                                          'h2', env.domain1, env.https_only_tcp_port,
                                          'h3', env.domain1, env.https_only_tcp_port)
        r = curl.http_download(urls=[urln], extra_args=[
            '--alt-svc', altsvc_file
        ])
        # Should try a QUIC connection that fails and fallback to h2
        r.check_exit_code(0)
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '2'

    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_06_21_as_follow_h3h1(self, env: Env, httpd, configures_httpd, nghttpx):
        # With '--http3` an Alt-Svc redirection from h3 to h1 is allowed
        # write an alt-svc file the advises h1 instead of h3
        curl = CurlClient(env=env)
        asfile = curl.mk_altsvc_file('test_12',
                                     'h3', env.domain1, env.https_only_tcp_port,
                                     'http/1.1', env.domain1, env.https_only_tcp_port)
        urln = f'https://{env.domain1}:{env.https_only_tcp_port}/data.json'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}', '--http3'
        ])
        r.check_response(count=1, http_status=200)
        # We expect the connection to be preferring HTTP/1.1 in the ALPN
        assert r.total_connects == 1, f'{r.dump_logs()}'
        re_m = re.compile(r'.* ALPN: curl offers http/1.1,h2')
        lines = [line for line in r.trace_lines if re_m.match(line)]
        assert len(lines), f'{r.dump_logs()}'

    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_06_22_as_ignore_h3h1(self, env: Env, httpd, configures_httpd, nghttpx):
        # With '--http3-only` an Alt-Svc redirection from h3 to h1 is ignored
        # write an alt-svc file the advises h1 instead of h3
        curl = CurlClient(env=env)
        asfile = curl.mk_altsvc_file('test_12',
                                     'h3', env.domain1, env.https_port,
                                     'http/1.1', env.domain1, env.https_port)
        urln = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}', '--http3-only'
        ])
        r.check_response(count=1, http_status=200)
        # We expect the connection to be stay on h3, since we used --http3-only
        assert r.total_connects == 1
        assert r.stats[0]['http_version'] == '3', f'{r.stats}'

    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_06_23_as_ignore_h2h3(self, env: Env, httpd, configures_httpd, nghttpx):
        # With '--http2` an Alt-Svc redirection from h2 to h3 is ignored
        # write an alt-svc file that advises h3 instead of h2
        curl = CurlClient(env=env)
        asfile = curl.mk_altsvc_file('test_12',
                                     'h2', env.domain1, env.https_port,
                                     'h3', env.domain1, env.h3_port)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}', '--http2'
        ])
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '2', f'{r.stats}'

    # download using HTTP/3 on available server with alt-svc to h2, use h2
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    def test_06_24_h3_altsvc_h2_used(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        urln = f'https://{env.domain1}:{env.https_only_tcp_port}/data.json'
        altsvc_file = curl.mk_altsvc_file('test_12',
                                          'h3', env.domain1, env.https_only_tcp_port,
                                          'h2', env.domain1, env.https_only_tcp_port)
        r = curl.http_download(urls=[urln], extra_args=[
            '--http3', '--alt-svc', altsvc_file
        ])
        r.check_exit_code(0)
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '2'
