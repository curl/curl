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
import filecmp
import logging
import os
import re
import time
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestProxyAuth:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx_fwd):
        if env.have_nghttpx():
            nghttpx_fwd.start_if_needed()
        httpd.clear_extra_configs()
        httpd.set_proxy_auth(True)
        httpd.reload()
        yield
        httpd.set_proxy_auth(False)
        httpd.reload()

    def set_tunnel_proto(self, proto):
        if proto == 'h2':
            os.environ['CURL_PROXY_TUNNEL_H2'] = '1'
            return 'HTTP/2'
        else:
            os.environ.pop('CURL_PROXY_TUNNEL_H2', None)
            return 'HTTP/1.1'

    def get_tunnel_proto_used(self, curl: CurlClient):
        assert os.path.exists(curl.trace_file)
        for l in open(curl.trace_file).readlines():
            m = re.match(r'.* == Info: CONNECT tunnel: (\S+) negotiated', l)
            if m:
                return m.group(1)
        return None

    # download via http: proxy (no tunnel), no auth
    def test_13_01_proxy_no_auth(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        r.check_response(count=1, http_status=407)

    # download via http: proxy (no tunnel), auth
    def test_13_02_proxy_auth(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy-user', 'proxy:proxy',
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        r.check_response(count=1, http_status=200)

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_13_03_proxys_no_auth(self, env: Env, httpd, nghttpx_fwd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'https://{env.proxy_domain}:{env.pts_port()}/',
                                 '--resolve', f'{env.proxy_domain}:{env.pts_port()}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        r.check_response(count=1, http_status=407)

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_13_04_proxys_auth(self, env: Env, httpd, nghttpx_fwd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy-user', 'proxy:proxy',
                                 '--proxy', f'https://{env.proxy_domain}:{env.pts_port()}/',
                                 '--resolve', f'{env.proxy_domain}:{env.pts_port()}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        r.check_response(count=1, http_status=200)

    def test_13_05_tunnel_http_no_auth(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        # expect "COULD_NOT_CONNECT"
        r.check_response(exitcode=56, http_status=None)

    def test_13_06_tunnel_http_auth(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy-user', 'proxy:proxy',
                                 '--proxy', f'http://{env.proxy_domain}:{env.proxy_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.proxy_port}:127.0.0.1',
                               ])
        r.check_response(count=1, http_status=200)

    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    def test_13_07_tunnels_no_auth(self, env: Env, httpd, proto, tunnel, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        exp_tunnel_proto = self.set_tunnel_proto(tunnel)
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               with_headers=True, with_trace=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy', f'https://{env.proxy_domain}:{env.pts_port(tunnel)}/',
                                 '--resolve', f'{env.proxy_domain}:{env.pts_port(tunnel)}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        # expect "COULD_NOT_CONNECT"
        r.check_response(exitcode=56, http_status=None)
        assert self.get_tunnel_proto_used(curl) == exp_tunnel_proto

    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    def test_13_08_tunnels_auth(self, env: Env, httpd, proto, tunnel, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        exp_tunnel_proto = self.set_tunnel_proto(tunnel)
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               with_headers=True, with_trace=True,
                               extra_args=[
                                 '--proxytunnel',
                                 '--proxy-user', 'proxy:proxy',
                                 '--proxy', f'https://{env.proxy_domain}:{env.pts_port(tunnel)}/',
                                 '--resolve', f'{env.proxy_domain}:{env.pts_port(tunnel)}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        r.check_response(count=1, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')
        assert self.get_tunnel_proto_used(curl) == exp_tunnel_proto

