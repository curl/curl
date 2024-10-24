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
from datetime import datetime, timedelta
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
class TestReuse:

    # check if HTTP/1.1 handles 'Connection: close' correctly
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_01_h1_conn_close(self, env: Env,
                                 httpd, nghttpx, repeat, proto):
        httpd.clear_extra_configs()
        httpd.set_extra_config('base', [
            'MaxKeepAliveRequests 1',
        ])
        httpd.reload()
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
    def test_12_02_h1_conn_timeout(self, env: Env,
                                   httpd, nghttpx, repeat, proto):
        httpd.clear_extra_configs()
        httpd.set_extra_config('base', [
            'KeepAliveTimeout 1',
        ])
        httpd.reload()
        count = 5
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--rate', '30/m',
        ])
        r.check_response(count=count, http_status=200)
        # Connections time out on server before we send another request,
        assert r.total_connects == count

    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_12_03_alt_svc_h2h3(self, env: Env, httpd, nghttpx):
        httpd.clear_extra_configs()
        httpd.reload()
        count = 2
        # write a alt-svc file the advises h3 instead of h2
        asfile = os.path.join(env.gen_dir, 'alt-svc-12_03.txt')
        ts = datetime.now() + timedelta(hours=24)
        expires = f'{ts.year:04}{ts.month:02}{ts.day:02} {ts.hour:02}:{ts.minute:02}:{ts.second:02}'
        with open(asfile, 'w') as fd:
            fd.write(f'h2 {env.domain1} {env.https_port} h3 {env.domain1} {env.https_port} "{expires}" 0 0')
        log.info(f'altscv: {open(asfile).readlines()}')
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}',
        ])
        r.check_response(count=count, http_status=200)
        # We expect the connection to be reused
        assert r.total_connects == 1
        for s in r.stats:
            assert s['http_version'] == '3', f'{s}'

    def test_12_04_alt_svc_h3h2(self, env: Env, httpd, nghttpx):
        httpd.clear_extra_configs()
        httpd.reload()
        count = 2
        # write a alt-svc file the advises h2 instead of h3
        asfile = os.path.join(env.gen_dir, 'alt-svc-12_04.txt')
        ts = datetime.now() + timedelta(hours=24)
        expires = f'{ts.year:04}{ts.month:02}{ts.day:02} {ts.hour:02}:{ts.minute:02}:{ts.second:02}'
        with open(asfile, 'w') as fd:
            fd.write(f'h3 {env.domain1} {env.https_port} h2 {env.domain1} {env.https_port} "{expires}" 0 0')
        log.info(f'altscv: {open(asfile).readlines()}')
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}',
        ])
        r.check_response(count=count, http_status=200)
        # We expect the connection to be reused
        assert r.total_connects == 1
        for s in r.stats:
            assert s['http_version'] == '2', f'{s}'

    def test_12_05_alt_svc_h3h1(self, env: Env, httpd, nghttpx):
        httpd.clear_extra_configs()
        httpd.reload()
        count = 2
        # write a alt-svc file the advises h1 instead of h3
        asfile = os.path.join(env.gen_dir, 'alt-svc-12_05.txt')
        ts = datetime.now() + timedelta(hours=24)
        expires = f'{ts.year:04}{ts.month:02}{ts.day:02} {ts.hour:02}:{ts.minute:02}:{ts.second:02}'
        with open(asfile, 'w') as fd:
            fd.write(f'h3 {env.domain1} {env.https_port} http/1.1 {env.domain1} {env.https_port} "{expires}" 0 0')
        log.info(f'altscv: {open(asfile).readlines()}')
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], with_stats=True, extra_args=[
            '--alt-svc', f'{asfile}',
        ])
        r.check_response(count=count, http_status=200)
        # We expect the connection to be reused
        assert r.total_connects == 1
        # When using http/1.1 from alt-svc, we ALPN-negotiate 'h2,http/1.1' anyway
        # which means our server gives us h2
        for s in r.stats:
            assert s['http_version'] == '2', f'{s}'
