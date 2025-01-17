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

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestShutdown:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=indir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=indir, fname="data-1m", fsize=1024*1024)

    # check with `tcpdump` that we see curl TCP RST packets
    @pytest.mark.skipif(condition=not Env.tcpdump(), reason="tcpdump not available")
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_19_01_check_tcp_rst(self, env: Env, httpd, proto):
        if env.ci_run:
            pytest.skip("seems not to work in CI")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_tcpdump=True, extra_args=[
            '--parallel'
        ])
        r.check_response(http_status=200, count=2)
        assert r.tcpdump
        assert len(r.tcpdump.stats) != 0, f'Expected TCP RSTs packets: {r.tcpdump.stderr}'

    # check with `tcpdump` that we do NOT see TCP RST when CURL_GRACEFUL_SHUTDOWN set
    @pytest.mark.skipif(condition=not Env.tcpdump(), reason="tcpdump not available")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_19_02_check_shutdown(self, env: Env, httpd, proto):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        curl = CurlClient(env=env, run_env={
            'CURL_GRACEFUL_SHUTDOWN': '2000',
            'CURL_DEBUG': 'ssl,tcp'
        })
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_tcpdump=True, extra_args=[
            '--parallel'
        ])
        r.check_response(http_status=200, count=2)
        assert r.tcpdump
        assert len(r.tcpdump.stats) == 0, 'Unexpected TCP RSTs packets'

    # run downloads where the server closes the connection after each request
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_19_03_shutdown_by_server(self, env: Env, httpd, proto):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        count = 10
        curl = CurlClient(env=env, run_env={
            'CURL_GRACEFUL_SHUTDOWN': '2000',
            'CURL_DEBUG': 'ssl'
        })
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/tweak/?'\
            f'id=[0-{count-1}]&with_cl&close'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(http_status=200, count=count)
        shutdowns = [line for line in r.trace_lines
                     if re.match(r'.*CCACHE\] shutdown #\d+, done=1', line)]
        assert len(shutdowns) == count, f'{shutdowns}'

    # run downloads with CURLOPT_FORBID_REUSE set, meaning *we* close
    # the connection after each request
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_19_04_shutdown_by_curl(self, env: Env, httpd, proto):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        count = 10
        docname = 'data.json'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env, run_env={
            'CURL_GRACEFUL_SHUTDOWN': '2000',
            'CURL_DEBUG': 'ssl'
        })
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-f', '-V', proto, url
        ])
        r.check_exit_code(0)
        shutdowns = [line for line in r.trace_lines
                     if re.match(r'.*CCACHE\] shutdown #\d+, done=1', line)]
        assert len(shutdowns) == count, f'{shutdowns}'

    # run event-based downloads with CURLOPT_FORBID_REUSE set, meaning *we* close
    # the connection after each request
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_19_05_event_shutdown_by_server(self, env: Env, httpd, proto):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        count = 10
        curl = CurlClient(env=env, run_env={
            # forbid connection reuse to trigger shutdowns after transfer
            'CURL_FORBID_REUSE': '1',
            # make socket receives block 50% of the time to delay shutdown
            'CURL_DBG_SOCK_RBLOCK': '50',
            'CURL_DEBUG': 'ssl'
        })
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/tweak/?'\
            f'id=[0-{count-1}]&with_cl&'
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--test-event'
        ])
        r.check_response(http_status=200, count=count)
        # check that we closed all connections
        closings = [line for line in r.trace_lines
                    if re.match(r'.*CCACHE\] closing #\d+', line)]
        assert len(closings) == count, f'{closings}'
        # check that all connection sockets were removed from event
        removes = [line for line in r.trace_lines
                   if re.match(r'.*socket cb: socket \d+ REMOVED', line)]
        assert len(removes) == count, f'{removes}'

    # check graceful shutdown on multiplexed http
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_19_06_check_shutdown(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        curl = CurlClient(env=env, run_env={
            'CURL_GRACEFUL_SHUTDOWN': '2000',
            'CURL_DEBUG': 'all'
        })
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_tcpdump=True, extra_args=[
            '--parallel'
        ])
        r.check_response(http_status=200, count=2)
        # check connection cache closings
        shutdowns = [line for line in r.trace_lines
                     if re.match(r'.*CCACHE\] shutdown #\d+, done=1', line)]
        assert len(shutdowns) == 1, f'{shutdowns}'
