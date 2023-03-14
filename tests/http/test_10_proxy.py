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

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        push_dir = os.path.join(httpd.docs_dir, 'push')
        if not os.path.exists(push_dir):
            os.makedirs(push_dir)
        httpd.clear_extra_configs()
        httpd.reload()

    # download via http: proxy (no tunnel)
    def test_10_01_proxy_http(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)

    # download via https: proxy (no tunnel)
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    def test_10_02_proxy_https(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'https://{env.proxy_domain}:{env.proxys_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxys_port}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)

    # download http: via http: proxytunnel
    def test_10_03_proxytunnel_http(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)

    # download http: via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    def test_10_04_proxy_https(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'https://{env.proxy_domain}:{env.proxys_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxys_port}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)

    # download https: with proto via http: proxytunnel
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_10_05_proxytunnel_http(self, env: Env, httpd, proto, repeat):
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               with_headers=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)
        exp_proto = 'HTTP/2' if proto == 'h2' else 'HTTP/1.1'
        assert r.response['protocol'] == exp_proto

    # download https: with proto via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_10_06_proxy_https(self, env: Env, httpd, proto, repeat):
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               with_headers=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'https://{env.proxy_domain}:{env.proxys_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxys_port}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)
        exp_proto = 'HTTP/2' if proto == 'h2' else 'HTTP/1.1'
        assert r.response['protocol'] == exp_proto

