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
import difflib
import filecmp
import json
import logging
import os
from datetime import timedelta
import pytest

from testenv import Env, CurlClient, LocalClient, ExecResult


log = logging.getLogger(__name__)


class TestSSLUse:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    def test_17_01_sslinfo_plain(self, env: Env, httpd, nghttpx, repeat):
        proto = 'http/1.1'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.json['HTTPS'] == 'on', f'{r.json}'
        assert 'SSL_SESSION_ID' in r.json, f'{r.json}'
        assert 'SSL_SESSION_RESUMED' in r.json, f'{r.json}'
        assert r.json['SSL_SESSION_RESUMED'] == 'Initial', f'{r.json}'

    @pytest.mark.parametrize("tls_max", ['1.2', '1.3'])
    def test_17_02_sslinfo_reconnect(self, env: Env, httpd, nghttpx, tls_max, repeat):
        proto = 'http/1.1'
        count = 3
        exp_resumed = 'Resumed'
        xargs = ['--sessionid', '--tls-max', tls_max, f'--tlsv{tls_max}']
        if env.curl_uses_lib('gnutls'):
            if tls_max == '1.3':
                exp_resumed = 'Initial'  # 1.2 works in gnutls, but 1.3 does not, TODO
        if env.curl_uses_lib('libressl'):
            if tls_max == '1.3':
                exp_resumed = 'Initial'  # 1.2 works in libressl, but 1.3 does not, TODO
        if env.curl_uses_lib('wolfssl'):
            xargs = ['--sessionid', f'--tlsv{tls_max}']
            if tls_max == '1.3':
                exp_resumed = 'Initial'  # 1.2 works in wolfssl, but 1.3 does not, TODO
        if env.curl_uses_lib('rustls-ffi'):
            exp_resumed = 'Initial'  # rustls does not support sessions, TODO
        if env.curl_uses_lib('bearssl') and tls_max == '1.3':
            pytest.skip('BearSSL does not support TLSv1.3')
        if env.curl_uses_lib('mbedtls') and tls_max == '1.3' and \
                not env.curl_lib_version_at_least('mbedtls', '3.6.0'):
            pytest.skip('mbedtls TLSv1.3 support requires at least 3.6.0')

        curl = CurlClient(env=env)
        # tell the server to close the connection after each request
        urln = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo?'\
               f'id=[0-{count-1}]&close'
        r = curl.http_download(urls=[urln], alpn_proto=proto, with_stats=True,
                               extra_args=xargs)
        r.check_response(count=count, http_status=200)
        # should have used one connection for each request, sessions after
        # first should have been resumed
        assert r.total_connects == count, r.dump_logs()
        for i in range(count):
            dfile = curl.download_file(i)
            assert os.path.exists(dfile)
            with open(dfile) as f:
                djson = json.load(f)
            assert djson['HTTPS'] == 'on', f'{i}: {djson}'
            if i == 0:
                assert djson['SSL_SESSION_RESUMED'] == 'Initial', f'{i}: {djson}'
            else:
                assert djson['SSL_SESSION_RESUMED'] == exp_resumed, f'{i}: {djson}'

    # use host name with trailing dot, verify handshake
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_03_trailing_dot(self, env: Env, httpd, nghttpx, repeat, proto):
        if env.curl_uses_lib('gnutls'):
            pytest.skip("gnutls does not match hostnames with trailing dot")
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = f'{env.domain1}.'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'
        if proto != 'h3':  # we proxy h3
            # the SNI the server received is without trailing dot
            assert r.json['SSL_TLS_SNI'] == env.domain1, f'{r.json}'

    # use host name with double trailing dot, verify handshake
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_04_double_dot(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('wolfssl'):
            pytest.skip("wolfSSL HTTP/3 peer verification does not properly check")
        curl = CurlClient(env=env)
        domain = f'{env.domain1}..'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[
            '-H', f'Host: {env.domain1}',
        ])
        if r.exit_code == 0:
            assert r.json, f'{r.stdout}'
            # the SNI the server received is without trailing dot
            if proto != 'h3':  # we proxy h3
                assert r.json['SSL_TLS_SNI'] == env.domain1, f'{r.json}'
            assert False, f'should not have succeeded: {r.json}'
        # 7 - rustls rejects a servername with .. during setup
        # 35 - libressl rejects setting an SNI name with trailing dot
        # 60 - peer name matching failed against certificate
        assert r.exit_code in [7, 35, 60], f'{r}'

    # use ip address for connect
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_05_ip_addr(self, env: Env, httpd, nghttpx, repeat, proto):
        if env.curl_uses_lib('bearssl'):
            pytest.skip("bearssl does not support cert verification with IP addresses")
        if env.curl_uses_lib('mbedtls'):
            pytest.skip("mbedtls does not support cert verification with IP addresses")
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = f'127.0.0.1'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'
        if proto != 'h3':  # we proxy h3
            # the SNI should not have been used
            assert 'SSL_TLS_SNI' not in r.json, f'{r.json}'

    # use localhost for connect
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_06_localhost(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = f'localhost'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'
        if proto != 'h3':  # we proxy h3
            assert r.json['SSL_TLS_SNI'] == domain, f'{r.json}'

    # test setting cipher suites, the AES 256 ciphers are disabled in the test server
    @pytest.mark.parametrize("ciphers, succeed", [
        [[0x1301], True],
        [[0x1302], False],
        [[0x1303], True],
        [[0x1302, 0x1303], True],
        [[0xC02B, 0xC02F], True],
        [[0xC02C, 0xC030], False],
        [[0xCCA9, 0xCCA8], True],
        [[0xC02C, 0xC030, 0xCCA9, 0xCCA8], True],
    ])
    def test_17_07_ssl_ciphers(self, env: Env, httpd, nghttpx, ciphers, succeed, repeat):
        cipher_table = {
           0x1301: 'TLS_AES_128_GCM_SHA256',
           0x1302: 'TLS_AES_256_GCM_SHA384',
           0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
           0xC02B: 'ECDHE-ECDSA-AES128-GCM-SHA256',
           0xC02F: 'ECDHE-RSA-AES128-GCM-SHA256',
           0xC02C: 'ECDHE-ECDSA-AES256-GCM-SHA384',
           0xC030: 'ECDHE-RSA-AES256-GCM-SHA384',
           0xCCA9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
           0xCCA8: 'ECDHE-RSA-CHACHA20-POLY1305',
        }
        cipher_names = list(map(cipher_table.get, ciphers))
        proto = 'http/1.1'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo'
        extra_args = []
        if env.curl_uses_lib('gnutls'):
            pytest.skip('gnutls does not support setting ciphers by name')
        if env.curl_uses_lib('rustls-ffi'):
            pytest.skip('rustls-ffi does not support setting ciphers')
        if ciphers[0] & 0xFF00 == 0x1300:
            # test setting TLSv1.3 ciphers
            if env.curl_uses_lib('bearssl'):
                pytest.skip('bearssl does not support TLSv1.3')
            elif env.curl_uses_lib('sectransp'):
                pytest.skip('sectransp does not support TLSv1.3')
            elif env.curl_uses_lib('boringssl'):
                pytest.skip('boringssl does not support setting TLSv1.3 ciphers')
            elif env.curl_uses_lib('mbedtls'):
                if not env.curl_lib_version_at_least('mbedtls', '3.6.0'):
                    pytest.skip('mbedtls TLSv1.3 support requires at least 3.6.0')
                extra_args = ['--ciphers', ':'.join(cipher_names)]
            elif env.curl_uses_lib('wolfssl'):
                extra_args = ['--ciphers', ':'.join(cipher_names)]
            else:
                extra_args = ['--tls13-ciphers', ':'.join(cipher_names)]
        else:
            # test setting TLSv1.2 ciphers
            if env.curl_uses_lib('schannel'):
                pytest.skip('schannel does not support setting TLSv1.2 ciphers by name')
            elif env.curl_uses_lib('wolfssl'):
                # setting tls version is botched with wolfssl: setting max (--tls-max)
                # is not supported, setting min (--tlsv1.*) actually also sets max
                extra_args = ['--tlsv1.2', '--ciphers', ':'.join(cipher_names)]
            else:
                # the server supports TLSv1.3, so to test TLSv1.2 ciphers we set tls-max
                extra_args = ['--tls-max', '1.2', '--ciphers', ':'.join(cipher_names)]
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=extra_args)
        if succeed:
            assert r.exit_code == 0, f'{r}'
            assert r.json['HTTPS'] == 'on', f'{r.json}'
            assert 'SSL_CIPHER' in r.json, f'{r.json}'
            assert r.json['SSL_CIPHER'] in cipher_names, f'{r.json}'
        else:
            assert r.exit_code != 0, f'{r}'
