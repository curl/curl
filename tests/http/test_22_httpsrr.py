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
import socket
import socketserver
import ssl
import threading
from typing import Generator

import pytest
from testenv import CurlClient, Dnsd, Env

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
@pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPSRR'), reason="no HTTPSRR support")
class TestHTTPSRR:

    @pytest.fixture(scope='class')
    @classmethod
    def dnsd(cls, env: Env) -> Generator[Dnsd, None, None]:
        dnsd = Dnsd(env=env)
        assert dnsd.initial_start()
        yield dnsd
        dnsd.stop()

    def dns_settings(self, dns_method, dnsd):
        run_env = os.environ.copy()
        run_env['CURL_QUICK_EXIT'] = '1'
        run_env['CURL_DEBUG'] = 'dns,https-connect'
        run_env['CURL_DBG_AWAIT_HTTPSRR'] = '1'
        xargs = []
        if dns_method == 'DoH':
            if not Env.curl_can_doh():
                pytest.skip(reason="curl built without DoH")
            xargs = ['--doh-insecure', '--doh-url', f'http://127.0.0.1:{dnsd.port}/']
        else:
            if not Env.curl_override_dns():
                pytest.skip(reason="no DNS override")
            run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        return run_env, xargs

    # dnsd a HTTPS-RR that prefers HTTP/1.1.
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_01_httpsrr_h1(self, env: Env, httpd, dnsd, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 . alpn=http/1.1'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['http_version'] == '1.1', f'{r}'

    # dnsd a HTTPS-RR that prefers HTTP/2, this overrides the --http3 option.
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_02_httpsrr_h3(self, env: Env, httpd, dnsd, nghttpx, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 . alpn=h2'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        xargs.append('--http3')
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['http_version'] == '2', f'{r}'

    # dnsd a HTTPS-RR that prefers HTTP/3.
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_03_httpsrr_h3(self, env: Env, httpd, dnsd, nghttpx, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 . alpn=h3,h2'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['http_version'] == '3', f'{r}'

    # dnsd a HTTPS-RR that prefers HTTP/1.1 for another target, so ignored.
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_04_httpsrr_wrong_target(self, env: Env, httpd, dnsd, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 another alpn=http/1.1'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['http_version'] == '2', f'{r}'

    # dnsd a HTTPS-RR with no-default-alpn, ignored by curl for now
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_05_httpsrr_no_default_alpn(self, env: Env, httpd, dnsd, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 . no-default-alpn alpn=http/1.1'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['http_version'] == '2', f'{r}'

    # download https: via https: proxytunnel
    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                        reason='curl lacks HTTPS-proxy support')
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx available")
    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    def test_22_06_httpsrr_proxy(self, env: Env, httpd, nghttpx_fwd, dnsd, dns_method):
        dnsd.set_answers(addr_a=['127.0.0.1'],
                         https=['10 . alpn=http/1.1'])
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://localhost:{env.https_port}/data.json'
        xargs.extend(curl.get_proxy_args(tunnel=True))
        r = curl.http_download(urls=[url], alpn_proto='h2', with_stats=True,
                               extra_args=xargs)
        r.check_response(count=1, http_status=200)
        assert r.stats[0]['http_version'] == '1.1', f'{r}'

    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    @pytest.mark.parametrize("http_version", ["--http1.1", "--http2-prior-knowledge"])
    def test_22_07_httpsrr_cert_error(self, env: Env, httpd, dnsd,
                                      dns_method, http_version):
        if http_version == '--http2-prior-knowledge' and not env.have_h2_curl():
            pytest.skip("curl without h2")
        dnsd.set_answers(addr_a=['127.0.0.1'], delay_https_ms=5000)
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        # Start TLS while HTTPS-RR is pending, as a normal transfer would.
        run_env.pop('CURL_DBG_AWAIT_HTTPSRR')
        xargs.extend([http_version, '--max-time', '2'])
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.expired_domain}:{env.https_port}/'
        r = curl.http_download(urls=[url], extra_args=xargs)
        r.check_exit_code(60)
        r.check_stats(count=1, http_status=0, exitcode=60)
        # Only OpenSSL-compatible backends and GnuTLS report this value.
        if env.curl_uses_any_libs(['openssl', 'quictls', 'libressl',
                                  'boringssl', 'aws-lc', 'gnutls']):
            assert r.stats[0]['ssl_verify_result'] != 0, r.dump_logs()

    @pytest.mark.parametrize("dns_method", ["DNS", "DoH"])
    @pytest.mark.parametrize("http_version", ["--http1.1", "--http2-prior-knowledge"])
    def test_22_08_httpsrr_tls_error(self, env: Env, httpd, dnsd,
                                     configures_httpd, dns_method, http_version):
        if http_version == '--http2-prior-knowledge' and not env.have_h2_curl():
            pytest.skip("curl without h2")
        httpd.set_extra_config('base', ['SSLProtocol TLSv1.3'])
        httpd.reload_if_config_changed()
        dnsd.set_answers(addr_a=['127.0.0.1'], delay_https_ms=5000)
        run_env, xargs = self.dns_settings(dns_method, dnsd)
        run_env.pop('CURL_DBG_AWAIT_HTTPSRR')
        xargs.extend([http_version, '--tls-max', '1.2', '--max-time', '2'])
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.domain1}:{env.https_port}/'
        r = curl.http_download(urls=[url], extra_args=xargs)
        r.check_exit_code(35)
        r.check_stats(count=1, http_status=0, exitcode=35)

    @pytest.mark.skipif(condition=not Env.have_h2_curl(), reason="curl without h2")
    @pytest.mark.skipif(condition=not ssl.HAS_ALPN, reason="Python TLS without ALPN")
    def test_22_09_httpsrr_h2_to_h1(self, env: Env, dnsd):
        # The first peer offers h2 but has a certificate for another host.
        # A delayed HTTPS-RR can still select h1 for a second, valid attempt.
        contexts = []
        for name, alpn in [(env.domain2, 'h2'), (env.domain1, 'http/1.1')]:
            credentials = env.get_credentials(name)
            assert credentials is not None, f'missing credentials for {name}'
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(credentials.cert_file, credentials.pkey_file)
            context.set_alpn_protocols([alpn])
            contexts.append(context)
        attempts, requests = [], []
        attempt_lock = threading.Lock()
        first_attempt = threading.Event()

        class Peer(socketserver.BaseRequestHandler):
            def handle(self):
                with attempt_lock:
                    context = contexts[min(len(attempts), len(contexts) - 1)]
                    attempts.append(1)
                first_attempt.set()
                self.request.settimeout(2)
                try:
                    with context.wrap_socket(self.request, server_side=True) as conn:
                        request = b''
                        while b'\r\n\r\n' not in request and len(request) < 16384:
                            data = conn.recv(4096)
                            if not data:
                                break
                            request += data
                        if request.startswith(b'GET ') and b'\r\n\r\n' in request:
                            requests.append(conn.selected_alpn_protocol())
                            conn.sendall(b'HTTP/1.1 200 OK\r\n'
                                         b'Content-Length: 2\r\n'
                                         b'Connection: close\r\n\r\nok')
                except (OSError, ssl.SSLError):
                    pass

        class DNSGate(socketserver.BaseRequestHandler):
            def handle(self):
                query, response_socket = self.request
                offset = 12
                while query[offset]:
                    offset += query[offset] + 1
                qtype = int.from_bytes(query[offset + 1:offset + 3], 'big')
                # Do not let the HTTPS answer select h1 for the first attempt.
                if qtype == 65 and not first_attempt.wait(timeout=5):
                    return
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward:
                    forward.settimeout(2)
                    forward.sendto(query, ('127.0.0.1', dnsd.port))
                    response = forward.recv(4096)
                    response_socket.sendto(response, self.client_address)

        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Peer) as peer, \
                socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNSGate) as gate:
            threads = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in (peer, gate)]
            for thread in threads:
                thread.start()
            try:
                dnsd.set_answers(addr_a=['127.0.0.1'],
                                 https=['10 . alpn=http/1.1'])
                run_env, xargs = self.dns_settings('DNS', dnsd)
                run_env.pop('CURL_DBG_AWAIT_HTTPSRR')
                run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{gate.server_address[1]}'
                xargs.extend(['--http2', '--max-time', '5'])
                curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
                url = f'https://{env.domain1}:{peer.server_address[1]}/'
                r = curl.http_download(urls=[url], extra_args=xargs)
                r.check_exit_code(0)
                r.check_stats(count=1, http_status=200, exitcode=0)
                assert r.stats[0]['http_version'] == '1.1', r.dump_logs()
                if env.curl_is_verbose():
                    assert any('1st attempt uses h2' in line
                               for line in r.trace_lines), r.dump_logs()
                assert len(attempts) == 2, r.dump_logs()
                assert requests == ['http/1.1'], r.dump_logs()
            finally:
                first_attempt.set()
                peer.shutdown()
                gate.shutdown()
                for thread in threads:
                    thread.join(timeout=3)
                    assert not thread.is_alive()
