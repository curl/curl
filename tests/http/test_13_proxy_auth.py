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
import re
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestProxyAuth:

    def httpd_configure(self, env, httpd):
        httpd.set_proxy_auth(True)
        httpd.reload_if_config_changed()

    def get_tunnel_proto_used(self, r: ExecResult):
        for line in r.trace_lines:
            m = re.match(r'.* CONNECT: \'(\S+)\' negotiated$', line)
            if m:
                return m.group(1)
        assert False, f'tunnel protocol not found in:\n{"".join(r.trace_lines)}'
        return None

    # download via http: proxy (no tunnel), no auth
    def test_13_01_proxy_no_auth(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=curl.get_proxy_args(proxys=False))
        r.check_response(count=1, http_status=407)

    # download via http: proxy (no tunnel), auth
    def test_13_02_proxy_auth(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=False)
        xargs.extend(['--proxy-user', 'proxy:proxy'])
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_13_03_proxys_no_auth(self, env: Env, httpd, configures_httpd, nghttpx_fwd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=True)
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=407)

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_13_04_proxys_auth(self, env: Env, httpd, configures_httpd, nghttpx_fwd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=True)
        xargs.extend(['--proxy-user', 'proxy:proxy'])
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)

    def test_13_05_tunnel_http_no_auth(self, env: Env, httpd, configures_httpd, nghttpx_fwd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=False, tunnel=True)
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        # expect "COULD_NOT_CONNECT"
        r.check_response(exitcode=56, http_status=None)

    def test_13_06_tunnel_http_auth(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=False, tunnel=True)
        xargs.extend(['--proxy-user', 'proxy:proxy'])
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)

    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason="needs curl verbose strings")
    @pytest.mark.parametrize("proto", Env.http_h1_h2_protos())
    @pytest.mark.parametrize("tunnel", Env.http_h1_h2_protos())
    def test_13_07_tunnels_no_auth(self, env: Env, httpd, configures_httpd, nghttpx_fwd, proto, tunnel):
        self.httpd_configure(env, httpd)
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        xargs = curl.get_proxy_args(proxys=True, tunnel=True, proto=tunnel)
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        # expect "COULD_NOT_CONNECT"
        r.check_response(exitcode=56, http_status=None)
        assert self.get_tunnel_proto_used(r) == tunnel

    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason="needs curl verbose strings")
    @pytest.mark.parametrize("proto", Env.http_h1_h2_protos())
    @pytest.mark.parametrize("tunnel", Env.http_h1_h2_protos())
    def test_13_08_tunnels_auth(self, env: Env, httpd, configures_httpd, nghttpx_fwd, proto, tunnel):
        self.httpd_configure(env, httpd)
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        xargs = curl.get_proxy_args(proxys=True, tunnel=True, proto=tunnel)
        xargs.extend(['--proxy-user', 'proxy:proxy'])
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')
        assert self.get_tunnel_proto_used(r) == tunnel

    @pytest.mark.skipif(condition=not Env.curl_has_feature('SPNEGO'),
                        reason='curl lacks SPNEGO support')
    def test_13_09_negotiate_http(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        run_env = os.environ.copy()
        run_env['https_proxy'] = f'http://127.0.0.1:{env.proxy_port}'
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://localhost:{env.https_port}/data.json'
        r1 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True, extra_args=[
            '--negotiate', '--proxy-user', 'proxy:proxy'
        ])
        r1.check_response(count=1, http_status=200)

    def test_13_10_tunnels_mixed_auth(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url1 = f'http://localhost:{env.http_port}/data.json?1'
        url2 = f'http://localhost:{env.http_port}/data.json?2'
        url3 = f'http://localhost:{env.http_port}/data.json?3'
        xargs1 = curl.get_proxy_args(proxys=False, tunnel=True)
        xargs1.extend(['--proxy-user', 'proxy:proxy']) # good auth
        xargs2 = curl.get_proxy_args(proxys=False, tunnel=True)
        xargs2.extend(['--proxy-user', 'ungood:ungood']) # bad auth
        xargs3 = curl.get_proxy_args(proxys=False, tunnel=True)
        # no auth
        r = curl.http_download(urls=[url1, url2, url3], alpn_proto='http/1.1', with_stats=True,
                               url_options={url1: xargs1, url2: xargs2, url3: xargs3})
        # only url1 succeeds, others fail, no connection reuse
        assert r.stats[0]['http_code'] == 200, f'{r.dump_logs()}'
        assert r.stats[1]['http_code'] == 0, f'{r.dump_logs()}'
        assert r.stats[2]['http_code'] == 0, f'{r.dump_logs()}'
        assert r.total_connects == 3, f'{r.dump_logs()}'
