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
import os
import pytest
import time

from testenv import Env, CurlClient

class TestH3Proxy:
    """Test cases for HTTP/3 and MASQUE proxy functionality using h2o"""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not Env.have_h2o():
            pytest.skip("no h2o available")

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_h2o(), reason="no h2o available")
    def test_h1_over_h3_proxytunnel(self, env: Env, h2o_server, h2o_proxy):
        """Test TCP over UDP (HTTP/1.1 GET request over HTTP/3 proxy tunnel)"""
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='h3', tunnel=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        # Check downloaded content
        download_file = os.path.join(curl.run_dir, 'download_#1.data')
        assert os.path.exists(download_file), f"Download file not found: {download_file}"
        with open(download_file, 'r') as f:
            content = f.read()
        assert '"message": "Hello from h2o HTTP/3 server"' in content, f"Unexpected response content: {content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_failure_h1_over_h3_proxytunnel(self, env: Env, httpd, nghttpx):
        """Test TCP over UDP (HTTP/1.1 GET request over HTTP/3 proxy tunnel (proxy doesn't support HTTP/3))"""
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
            '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxy-http3', '--proxytunnel', '--cacert', env.ca.cert_file, '--proxy-insecure'
        ]

        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        stderr_content = r.stderr
        assert 'failed: could not connect to server' in stderr_content.lower(), \
                f"Expected protocol/proxy error but got: {stderr_content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp2'),
                        reason='only supported with nghttp2')
    @pytest.mark.skipif(condition=not Env.have_h2o(), reason="no h2o available")
    def test_h2_over_h3_proxytunnel(self, env: Env, h2o_server, h2o_proxy):
        """Test TCP over UDP (HTTP/2 GET request over HTTP/3 proxy tunnel)"""
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='h3', tunnel=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='h2', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        # Check downloaded content
        download_file = os.path.join(curl.run_dir, 'download_#1.data')
        assert os.path.exists(download_file), f"Download file not found: {download_file}"
        with open(download_file, 'r') as f:
            content = f.read()
        assert '"message": "Hello from h2o HTTP/3 server"' in content, f"Unexpected response content: {content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp2'),
                        reason='only supported with nghttp2')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_failure_h2_over_h3_proxytunnel(self, env: Env, httpd, nghttpx):
        """Test TCP over UDP (HTTP/2 GET request over HTTP/3 proxy tunnel (proxy doesn't support HTTP/3))"""
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
            '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxy-http3', '--proxytunnel', '--cacert', env.ca.cert_file, '--proxy-insecure'
        ]

        r = curl.http_download(urls=[url], alpn_proto='h2', with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        stderr_content = r.stderr
        assert 'failed: could not connect to server' in stderr_content.lower(), \
                f"Expected protocol/proxy error but got: {stderr_content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_h2o(), reason="no h2o available")
    def test_h3_over_h3_proxyudptunnel(self, env: Env, h2o_server, h2o_proxy):
        """Test UDP over UDP (HTTP/3 GET request over HTTP/3 proxy UDP tunnel)"""
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='h3', tunneludp=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        # Check downloaded content
        download_file = os.path.join(curl.run_dir, 'download_#1.data')
        assert os.path.exists(download_file), f"Download file not found: {download_file}"
        with open(download_file, 'r') as f:
            content = f.read()
        assert '"message": "Hello from h2o HTTP/3 server"' in content, f"Unexpected response content: {content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_failure_h3_over_h3_proxyudptunnel(self, env: Env, httpd, nghttpx):
        """Test UDP over UDP (HTTP/3 GET request over HTTP/3 proxy UDP tunnel (proxy doesn't support HTTP/3))"""
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
            '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxy-http3', '--proxyudptunnel', '--cacert', env.ca.cert_file, '--proxy-insecure'
        ]

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        stderr_content = r.stderr
        assert 'failed: could not connect to server' in stderr_content.lower(), \
                f"Expected protocol/proxy error but got: {stderr_content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp2'),
                        reason='only supported with nghttp2')
    @pytest.mark.skipif(condition=not Env.have_h2o(), reason="no h2o available")
    def test_h3_over_h2_proxyudptunnel(self, env: Env, h2o_server, h2o_proxy):
        """Test UDP over TCP (HTTP/3 GET request over HTTP/2 proxy UDP tunnel)"""
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='h2', tunneludp=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        # Check downloaded content
        download_file = os.path.join(curl.run_dir, 'download_#1.data')
        assert os.path.exists(download_file), f"Download file not found: {download_file}"
        with open(download_file, 'r') as f:
            content = f.read()
        assert '"message": "Hello from h2o HTTP/3 server"' in content, f"Unexpected response content: {content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp2'),
                        reason='only supported with nghttp2')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_failure_h3_over_h2_proxyudptunnel(self, env: Env, httpd, nghttpx):
        """Test UDP over TCP (HTTP/3 GET request over HTTP/2 proxy UDP tunnel)"""
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
            '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxy-http2', '--proxyudptunnel', '--cacert', env.ca.cert_file, '--proxy-insecure'
        ]

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        stderr_content = r.stderr
        assert 'connect-udp response status 400' in stderr_content.lower(), \
                f"Expected protocol/proxy error but got: {stderr_content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_h2o(), reason="no h2o available")
    def test_h3_over_h1_proxyudptunnel(self, env: Env, h2o_server, h2o_proxy):
        """Test UDP over TCP (HTTP/3 GET request over HTTP/1.1 proxy UDP tunnel)"""
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='http/1.1', tunneludp=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        # Check downloaded content
        download_file = os.path.join(curl.run_dir, 'download_#1.data')
        assert os.path.exists(download_file), f"Download file not found: {download_file}"
        with open(download_file, 'r') as f:
            content = f.read()
        assert '"message": "Hello from h2o HTTP/3 server"' in content, f"Unexpected response content: {content}"


    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    @pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                        reason='only supported with nghttp3')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    def test_failure_h3_over_h1_proxyudptunnel(self, env: Env, httpd, nghttpx):
        """Test UDP over TCP (HTTP/3 GET request over HTTP/1.1 proxy UDP tunnel)"""
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
            '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxyudptunnel', '--cacert', env.ca.cert_file, '--proxy-insecure'
        ]

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        stderr_content = r.stderr
        assert 'connect-udp tunnel failed, response 404' in stderr_content.lower(), \
               f"Expected protocol/proxy error but got: {stderr_content}"