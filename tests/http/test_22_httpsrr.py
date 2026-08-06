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
from typing import Generator

import pytest
from testenv import CurlClient, Dnsd, Env

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
@pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPSRR'), reason="no HTTPSRR support")
class TestHTTPSRR:

    @pytest.fixture(scope='class')
    def dnsd(self, env: Env) -> Generator[Dnsd, None, None]:
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
