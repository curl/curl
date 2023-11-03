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
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx_fwd):
        push_dir = os.path.join(httpd.docs_dir, 'push')
        if not os.path.exists(push_dir):
            os.makedirs(push_dir)
        if env.have_nghttpx():
            nghttpx_fwd.start_if_needed()
        env.make_data_file(indir=env.gen_dir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)
        httpd.clear_extra_configs()
        httpd.reload()

    def get_tunnel_proto_used(self, r: ExecResult):
        for l in r.trace_lines:
            m = re.match(r'.* CONNECT tunnel: (\S+) negotiated$', l)
            if m:
                return m.group(1)
        assert False, f'tunnel protocol not found in:\n{"".join(r.trace_lines)}'
        return None

    # download via http: proxy (no tunnel)
    def test_10_01_proxy_http(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=curl.get_proxy_args(proxys=False))
        r.check_response(count=1, http_status=200)

    # download via https: proxy (no tunnel)
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_02_proxys_down(self, env: Env, httpd, nghttpx_fwd, proto, repeat):
        if proto == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proto=proto)
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')

    # upload via https: with proto (no tunnel)
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("fname, fcount", [
        ['data.json', 5],
        ['data-100k', 5],
        ['data-1m', 2]
    ])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(),
                        reason="no nghttpx available")
    def test_10_02_proxys_up(self, env: Env, httpd, nghttpx, proto,
                             fname, fcount, repeat):
        if proto == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        count = fcount
        srcfile = os.path.join(httpd.docs_dir, fname)
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/curltest/echo?id=[0-{count-1}]'
        xargs = curl.get_proxy_args(proto=proto)
        r = curl.http_upload(urls=[url], data=f'@{srcfile}', alpn_proto=proto,
                             extra_args=xargs)
        r.check_response(count=count, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')
        indata = open(srcfile).readlines()
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata

    # download http: via http: proxytunnel
    def test_10_03_proxytunnel_http(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(proxys=False, tunnel=True)
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)

    # download http: via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_04_proxy_https(self, env: Env, httpd, nghttpx_fwd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(tunnel=True)
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)

    # download https: with proto via http: proxytunnel
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    def test_10_05_proxytunnel_http(self, env: Env, httpd, proto, repeat):
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        xargs = curl.get_proxy_args(proxys=False, tunnel=True)
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')

    # download https: with proto via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_06_proxytunnel_https(self, env: Env, httpd, nghttpx_fwd, proto, tunnel, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json?[0-0]'
        xargs = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')
        assert self.get_tunnel_proto_used(r) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        srcfile = os.path.join(httpd.docs_dir, 'data.json')
        dfile = curl.download_file(0)
        assert filecmp.cmp(srcfile, dfile, shallow=False)

    # download many https: with proto via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("fname, fcount", [
        ['data.json', 100],
        ['data-100k', 20],
        ['data-1m', 5]
    ])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_07_pts_down_small(self, env: Env, httpd, nghttpx_fwd, proto,
                                  tunnel, fname, fcount, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        count = fcount
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/{fname}?[0-{count-1}]'
        xargs = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        r.check_response(count=count, http_status=200,
                         protocol='HTTP/2' if proto == 'h2' else 'HTTP/1.1')
        assert self.get_tunnel_proto_used(r) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        srcfile = os.path.join(httpd.docs_dir, fname)
        for i in range(count):
            dfile = curl.download_file(i)
            assert filecmp.cmp(srcfile, dfile, shallow=False)
        assert r.total_connects == 1, r.dump_logs()

    # upload many https: with proto via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("fname, fcount", [
        ['data.json', 50],
        ['data-100k', 20],
        ['data-1m', 5]
    ])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_08_upload_seq_large(self, env: Env, httpd, nghttpx, proto,
                                    tunnel, fname, fcount, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        count = fcount
        srcfile = os.path.join(httpd.docs_dir, fname)
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/curltest/echo?id=[0-{count-1}]'
        xargs = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r = curl.http_upload(urls=[url], data=f'@{srcfile}', alpn_proto=proto,
                             extra_args=xargs)
        assert self.get_tunnel_proto_used(r) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        r.check_response(count=count, http_status=200)
        indata = open(srcfile).readlines()
        for i in range(count):
            respdata = open(curl.response_file(i)).readlines()
            assert respdata == indata
        assert r.total_connects == 1, r.dump_logs()

    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_09_reuse_ser(self, env: Env, httpd, nghttpx_fwd, tunnel, repeat):
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url1 = f'https://localhost:{env.https_port}/data.json'
        url2 = f'http://localhost:{env.http_port}/data.json'
        xargs = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r = curl.http_download(urls=[url1, url2], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=2, http_status=200)
        assert self.get_tunnel_proto_used(r) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        if tunnel == 'h2':
            # TODO: we would like to reuse the first connection for the
            # second URL, but this is currently not possible
            # assert r.total_connects == 1
            assert r.total_connects == 2
        else:
            assert r.total_connects == 2

    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_10_10_reuse_proxy(self, env: Env, httpd, nghttpx_fwd, tunnel, repeat):
        # url twice via https: proxy separated with '--next', will reuse
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        proxy_args = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r1 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r1.check_response(count=1, http_status=200)
        assert self.get_tunnel_proto_used(r1) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        # get the args, duplicate separated with '--next'
        x2_args = r1.args[1:]
        x2_args.append('--next')
        x2_args.extend(proxy_args)
        r2 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=x2_args)
        r2.check_response(count=2, http_status=200)
        assert r2.total_connects == 1

    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('openssl'), reason="tls13-ciphers not supported")
    def test_10_11_noreuse_proxy_https(self, env: Env, httpd, nghttpx_fwd, tunnel, repeat):
        # different --proxy-tls13-ciphers, no reuse of connection for https:
        curl = CurlClient(env=env)
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        url = f'https://localhost:{env.https_port}/data.json'
        proxy_args = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r1 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r1.check_response(count=1, http_status=200)
        assert self.get_tunnel_proto_used(r1) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        # get the args, duplicate separated with '--next'
        x2_args = r1.args[1:]
        x2_args.append('--next')
        x2_args.extend(proxy_args)
        x2_args.extend(['--proxy-tls13-ciphers', 'TLS_AES_128_GCM_SHA256'])
        r2 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=x2_args)
        r2.check_response(count=2, http_status=200)
        assert r2.total_connects == 2

    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('openssl'), reason="tls13-ciphers not supported")
    def test_10_12_noreuse_proxy_http(self, env: Env, httpd, nghttpx_fwd, tunnel, repeat):
        # different --proxy-tls13-ciphers, no reuse of connection for http:
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        proxy_args = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r1 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r1.check_response(count=1, http_status=200)
        assert self.get_tunnel_proto_used(r1) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        # get the args, duplicate separated with '--next'
        x2_args = r1.args[1:]
        x2_args.append('--next')
        x2_args.extend(proxy_args)
        x2_args.extend(['--proxy-tls13-ciphers', 'TLS_AES_128_GCM_SHA256'])
        r2 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=x2_args)
        r2.check_response(count=2, http_status=200)
        assert r2.total_connects == 2

    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    @pytest.mark.parametrize("tunnel", ['http/1.1', 'h2'])
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('openssl'), reason="tls13-ciphers not supported")
    def test_10_13_noreuse_https(self, env: Env, httpd, nghttpx_fwd, tunnel, repeat):
        # different --tls13-ciphers on https: same proxy config
        if tunnel == 'h2' and not env.curl_uses_lib('nghttp2'):
            pytest.skip('only supported with nghttp2')
        curl = CurlClient(env=env)
        url = f'https://localhost:{env.https_port}/data.json'
        proxy_args = curl.get_proxy_args(tunnel=True, proto=tunnel)
        r1 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r1.check_response(count=1, http_status=200)
        assert self.get_tunnel_proto_used(r1) == 'HTTP/2' \
            if tunnel == 'h2' else 'HTTP/1.1'
        # get the args, duplicate separated with '--next'
        x2_args = r1.args[1:]
        x2_args.append('--next')
        x2_args.extend(proxy_args)
        x2_args.extend(['--tls13-ciphers', 'TLS_AES_128_GCM_SHA256'])
        r2 = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=x2_args)
        r2.check_response(count=2, http_status=200)
        assert r2.total_connects == 2
