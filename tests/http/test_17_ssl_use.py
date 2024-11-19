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
import json
import logging
import os
import re
import pytest

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestSSLUse:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        env.make_data_file(indir=httpd.docs_dir, fname="data-10k", fsize=10*1024)
        if env.have_h3():
            nghttpx.start_if_needed()

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, request, env, httpd):
        httpd.clear_extra_configs()
        if 'httpd' not in request.node._fixtureinfo.argnames:
            httpd.reload_if_config_changed()

    def test_17_01_sslinfo_plain(self, env: Env, nghttpx, repeat):
        proto = 'http/1.1'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.json['HTTPS'] == 'on', f'{r.json}'
        assert 'SSL_SESSION_ID' in r.json, f'{r.json}'
        assert 'SSL_SESSION_RESUMED' in r.json, f'{r.json}'
        assert r.json['SSL_SESSION_RESUMED'] == 'Initial', f'{r.json}'

    @pytest.mark.parametrize("tls_max", ['1.2', '1.3'])
    def test_17_02_sslinfo_reconnect(self, env: Env, tls_max):
        proto = 'http/1.1'
        count = 3
        exp_resumed = 'Resumed'
        xargs = ['--sessionid', '--tls-max', tls_max, f'--tlsv{tls_max}']
        if env.curl_uses_lib('libressl'):
            if tls_max == '1.3':
                exp_resumed = 'Initial'  # 1.2 works in LibreSSL, but 1.3 does not, TODO
        if env.curl_uses_lib('rustls-ffi'):
            exp_resumed = 'Initial'  # Rustls does not support sessions, TODO
        if env.curl_uses_lib('bearssl') and tls_max == '1.3':
            pytest.skip('BearSSL does not support TLSv1.3')
        if env.curl_uses_lib('mbedtls') and tls_max == '1.3' and \
           not env.curl_lib_version_at_least('mbedtls', '3.6.0'):
            pytest.skip('mbedtls TLSv1.3 session resume not working in 3.6.0')

        run_env = os.environ.copy()
        run_env['CURL_DEBUG'] = 'ssl'
        curl = CurlClient(env=env, run_env=run_env)
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
                assert djson['SSL_SESSION_RESUMED'] == 'Initial', f'{i}: {djson}\n{r.dump_logs()}'
            else:
                assert djson['SSL_SESSION_RESUMED'] == exp_resumed, f'{i}: {djson}\n{r.dump_logs()}'

    # use host name with trailing dot, verify handshake
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_03_trailing_dot(self, env: Env, proto):
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
    def test_17_04_double_dot(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
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
        # 7 - Rustls rejects a servername with .. during setup
        # 35 - LibreSSL rejects setting an SNI name with trailing dot
        # 60 - peer name matching failed against certificate
        assert r.exit_code in [7, 35, 60], f'{r}'

    # use ip address for connect
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_05_ip_addr(self, env: Env, proto):
        if env.curl_uses_lib('bearssl'):
            pytest.skip("BearSSL does not support cert verification with IP addresses")
        if env.curl_uses_lib('mbedtls'):
            pytest.skip("mbedTLS does use IP addresses in SNI")
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = '127.0.0.1'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'
        if proto != 'h3':  # we proxy h3
            # the SNI should not have been used
            assert 'SSL_TLS_SNI' not in r.json, f'{r.json}'

    # use localhost for connect
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_06_localhost(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = 'localhost'
        url = f'https://{env.authority_for(domain, proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'
        if proto != 'h3':  # we proxy h3
            assert r.json['SSL_TLS_SNI'] == domain, f'{r.json}'

    @staticmethod
    def gen_test_17_07_list():
        tls13_tests = [
            [None, True],
            [['TLS_AES_128_GCM_SHA256'], True],
            [['TLS_AES_256_GCM_SHA384'], False],
            [['TLS_CHACHA20_POLY1305_SHA256'], True],
            [['TLS_AES_256_GCM_SHA384',
              'TLS_CHACHA20_POLY1305_SHA256'], True],
        ]
        tls12_tests = [
            [None, True],
            [['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256'], True],
            [['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384'], False],
            [['ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305'], True],
            [['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384',
              'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305'], True],
        ]
        ret = []
        for tls_proto in ['TLSv1.3 +TLSv1.2', 'TLSv1.3', 'TLSv1.2']:
            for [ciphers13, succeed13] in tls13_tests:
                for [ciphers12, succeed12] in tls12_tests:
                    ret.append([tls_proto, ciphers13, ciphers12, succeed13, succeed12])
        return ret

    @pytest.mark.parametrize("tls_proto, ciphers13, ciphers12, succeed13, succeed12", gen_test_17_07_list())
    def test_17_07_ssl_ciphers(self, env: Env, httpd, tls_proto, ciphers13, ciphers12, succeed13, succeed12):
        # to test setting cipher suites, the AES 256 ciphers are disabled in the test server
        httpd.set_extra_config('base', [
            'SSLCipherSuite SSL'
                ' ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
                ':ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
            'SSLCipherSuite TLSv1.3'
                ' TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256',
            f'SSLProtocol {tls_proto}'
        ])
        httpd.reload_if_config_changed()
        proto = 'http/1.1'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo'
        # SSL backend specifics
        if env.curl_uses_lib('gnutls'):
            pytest.skip('GnuTLS does not support setting ciphers')
        elif env.curl_uses_lib('boringssl'):
            if ciphers13 is not None:
                pytest.skip('BoringSSL does not support setting TLSv1.3 ciphers')
        elif env.curl_uses_lib('schannel'):  # not in CI, so untested
            if ciphers12 is not None:
                pytest.skip('Schannel does not support setting TLSv1.2 ciphers by name')
        elif env.curl_uses_lib('bearssl'):
            if tls_proto == 'TLSv1.3':
                pytest.skip('BearSSL does not support TLSv1.3')
            tls_proto = 'TLSv1.2'
        elif env.curl_uses_lib('mbedtls') and not env.curl_lib_version_at_least('mbedtls', '3.6.0'):
            if tls_proto == 'TLSv1.3':
                pytest.skip('mbedTLS < 3.6.0 does not support TLSv1.3')
        elif env.curl_uses_lib('sectransp'):  # not in CI, so untested
            if tls_proto == 'TLSv1.3':
                pytest.skip('Secure Transport does not support TLSv1.3')
            tls_proto = 'TLSv1.2'
        # test
        extra_args = ['--tls13-ciphers', ':'.join(ciphers13)] if ciphers13 else []
        extra_args += ['--ciphers', ':'.join(ciphers12)] if ciphers12 else []
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=extra_args)
        if tls_proto != 'TLSv1.2' and succeed13:
            assert r.exit_code == 0, r.dump_logs()
            assert r.json['HTTPS'] == 'on', r.dump_logs()
            assert r.json['SSL_PROTOCOL'] == 'TLSv1.3', r.dump_logs()
            assert ciphers13 is None or r.json['SSL_CIPHER'] in ciphers13, r.dump_logs()
        elif tls_proto == 'TLSv1.2' and succeed12:
            assert r.exit_code == 0, r.dump_logs()
            assert r.json['HTTPS'] == 'on', r.dump_logs()
            assert r.json['SSL_PROTOCOL'] == 'TLSv1.2', r.dump_logs()
            assert ciphers12 is None or r.json['SSL_CIPHER'] in ciphers12, r.dump_logs()
        else:
            assert r.exit_code != 0, r.dump_logs()

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_08_cert_status(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if not env.curl_uses_lib('openssl') and \
            not env.curl_uses_lib('gnutls') and \
            not env.curl_uses_lib('quictls'):
            pytest.skip("TLS library does not support --cert-status")
        curl = CurlClient(env=env)
        domain = 'localhost'
        url = f'https://{env.authority_for(domain, proto)}/'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[
            '--cert-status'
        ])
        # CURLE_SSL_INVALIDCERTSTATUS, our certs have no OCSP info
        assert r.exit_code == 91, f'{r}'

    @staticmethod
    def gen_test_17_09_list():
        return [[tls_proto, max_ver, min_ver]
                for tls_proto in ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
                for max_ver in range(5)
                for min_ver in range(-2, 4)]

    @pytest.mark.parametrize("tls_proto, max_ver, min_ver", gen_test_17_09_list())
    def test_17_09_ssl_min_max(self, env: Env, httpd, tls_proto, max_ver, min_ver):
        httpd.set_extra_config('base', [
            f'SSLProtocol {tls_proto}',
            'SSLCipherSuite ALL:@SECLEVEL=0',
        ])
        httpd.reload_if_config_changed()
        proto = 'http/1.1'
        run_env = os.environ.copy()
        if env.curl_uses_lib('gnutls'):
            # we need to override any default system configuration since
            # we want to test all protocol versions. Ubuntu (or the GH image)
            # disable TSL1.0 and TLS1.1 system wide. We do not want.
            our_config = os.path.join(env.gen_dir, 'gnutls_config')
            if not os.path.exists(our_config):
                with open(our_config, 'w') as fd:
                    fd.write('# empty\n')
            run_env['GNUTLS_SYSTEM_PRIORITY_FILE'] = our_config
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/sslinfo'
        # SSL backend specifics
        if env.curl_uses_lib('bearssl'):
            supported = ['TLSv1', 'TLSv1.1', 'TLSv1.2', None]
        elif env.curl_uses_lib('sectransp'):  # not in CI, so untested
            supported = ['TLSv1', 'TLSv1.1', 'TLSv1.2', None]
        elif env.curl_uses_lib('gnutls'):
            supported = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        elif env.curl_uses_lib('quiche'):
            supported = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        else:  # most SSL backends dropped support for TLSv1.0, TLSv1.1
            supported = [None, None, 'TLSv1.2', 'TLSv1.3']
        # test
        extra_args = [[], ['--tlsv1'], ['--tlsv1.0'], ['--tlsv1.1'], ['--tlsv1.2'], ['--tlsv1.3']][min_ver+2] + \
            [['--tls-max', '1.0'], ['--tls-max', '1.1'], ['--tls-max', '1.2'], ['--tls-max', '1.3'], []][max_ver]
        extra_args.extend(['--trace-config', 'ssl'])
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=extra_args)
        if max_ver >= min_ver and tls_proto in supported[max(0, min_ver):min(max_ver, 3)+1]:
            assert r.exit_code == 0, f'extra_args={extra_args}\n{r.dump_logs()}'
            assert r.json['HTTPS'] == 'on', r.dump_logs()
            assert r.json['SSL_PROTOCOL'] == tls_proto, r.dump_logs()
        else:
            assert r.exit_code != 0, f'extra_args={extra_args}\n{r.dump_logs()}'

    def test_17_10_h3_session_reuse(self, env: Env, httpd, nghttpx):
        if not env.have_h3():
            pytest.skip("h3 not supported")
        if not env.curl_uses_lib('quictls') and \
            not env.curl_uses_lib('gnutls') and \
            not env.curl_uses_lib('wolfssl'):
            pytest.skip("QUIC session reuse not implemented")
        count = 2
        docname = 'data-10k'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-f',  # forbid reuse of connections
             '-r', f'{env.domain1}:{env.port_for("h3")}:127.0.0.1',
             '-V', 'h3', url
        ])
        r.check_exit_code(0)
        # check that TLS session was reused as expected
        reused_session = False
        for line in r.trace_lines:
            m = re.match(r'\[1-1] \* SSL reusing session.*', line)
            if m:
                reused_session = True
        assert reused_session, f'{r}\n{r.dump_logs()}'

    # use host name server has no certificate for
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_11_wrong_host(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = f'insecure.{env.tld}'
        url = f'https://{domain}:{env.port_for(proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 60, f'{r}'

    # use host name server has no cert for with --insecure
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_17_12_insecure(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        domain = f'insecure.{env.tld}'
        url = f'https://{domain}:{env.port_for(proto)}/curltest/sslinfo'
        r = curl.http_get(url=url, alpn_proto=proto, extra_args=[
            '--insecure'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.json, f'{r}'

    # connect to an expired certificate
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    def test_17_14_expired_cert(self, env: Env, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.expired_domain}:{env.port_for(proto)}/'
        r = curl.http_get(url=url, alpn_proto=proto)
        assert r.exit_code == 60, f'{r}'  # peer failed verification
        exp_trace = None
        match_trace = None
        if env.curl_uses_lib('openssl') or env.curl_uses_lib('quictls'):
            exp_trace = r'.*SSL certificate problem: certificate has expired$'
        elif env.curl_uses_lib('gnutls'):
            exp_trace = r'.*server verification failed: certificate has expired\..*'
        elif env.curl_uses_lib('wolfssl'):
            exp_trace = r'.*server verification failed: certificate has expired\.$'
        if exp_trace is not None:
            for line in r.trace_lines:
                if re.match(exp_trace, line):
                    match_trace = line
                    break
            assert match_trace, f'Did not find "{exp_trace}" in trace\n{r.dump_logs()}'
