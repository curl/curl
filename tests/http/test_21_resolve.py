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
from datetime import timedelta
from typing import Generator

import pytest
from testenv import CurlClient, Env, LocalClient, Dnsd

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
@pytest.mark.skipif(condition=not Env.curl_has_feature('AsynchDNS'), reason="needs AsynchDNS")
class TestResolve:

    @pytest.fixture(scope='class')
    def dnsd(self, env: Env) -> Generator[Dnsd, None, None]:
        dnsd = Dnsd(env=env)
        assert dnsd.initial_start()
        yield dnsd
        dnsd.stop()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-0k", fsize=0)

    # use .invalid host name that should never resolv
    def test_21_01_resolv_invalid_one(self, env: Env, httpd, nghttpx):
        count = 1
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = '5'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://test-{count}.http.curl.invalid/'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)

    # use .invalid host name, one after the other
    @pytest.mark.parametrize("delay_ms", [1, 50])
    def test_21_02_resolv_invalid_serial(self, env: Env, delay_ms, httpd, nghttpx):
        count = 10
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = f'{delay_ms}'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.http.curl.invalid/' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True)
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)

    # use .invalid host name, parallel
    @pytest.mark.parametrize("delay_ms", [1, 50])
    def test_21_03_resolv_invalid_parallel(self, env: Env, delay_ms, httpd, nghttpx):
        count = 20
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = f'{delay_ms}'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.http.curl.invalid/' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True, extra_args=[
            '--parallel'
        ])
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)

    # resolve first url with ipv6 only and fail that, resolve second
    # with ipv*, should succeed.
    def test_21_04_resolv_inv_v6(self, env: Env, httpd):
        count = 2
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_IPV6'] = '1'
        url = f'https://localhost:{env.https_port}/'
        client = LocalClient(name='cli_hx_download', env=env, run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        dfiles = [client.download_file(i) for i in range(count)]
        self._clean_files(dfiles)
        # let the first URL resolve via ipv6 only, which we force to fail
        r = client.run(args=[
            '-n', f'{count}', '-6', '-C', env.ca.cert_file, url
        ])
        r.check_exit_code(6)
        assert not os.path.exists(dfiles[0])
        assert os.path.exists(dfiles[1])

    # use .invalid host name, parallel, single resolve thread
    @pytest.mark.skipif(condition=not Env.curl_resolv_threaded(), reason="no threaded resolver")
    def test_21_05_resolv_single_thread(self, env: Env, httpd, nghttpx):
        count = 10
        delay_ms = 50
        run_env = os.environ.copy()
        run_env['CURL_DBG_RESOLV_FAIL_DELAY'] = f'{delay_ms}'
        run_env['CURL_DBG_RESOLV_MAX_THREADS'] = '1'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.http.curl.invalid/' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True, extra_args=[
            '--parallel', '-6'
        ])
        r.check_exit_code(6)
        r.check_stats(count=count, http_status=0, exitcode=6)
        assert r.duration > timedelta(milliseconds=count * delay_ms), f'{r}'

    # dnsd with no answers
    @pytest.mark.skipif(condition=not Env.curl_override_dns(), reason="no DNS override")
    def test_21_06_dnsd_empty(self, env: Env, httpd, dnsd):
        dnsd.set_answers()
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://test-dnsd.http.curl.invalid/'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(6)  # could not resolve host
        r.check_stats(count=1, http_status=0, exitcode=6)

    # dnsd with one answer for A
    @pytest.mark.skipif(condition=not Env.curl_override_dns(), reason="no DNS override")
    def test_21_07_dnsd_a(self, env: Env, httpd, dnsd):
        dnsd.set_answers(addr_a=['127.0.0.1'])
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['remote_ip'] == '127.0.0.1'

    # dnsd with one answer for AAAA
    @pytest.mark.skipif(condition=not Env.curl_override_dns(), reason="no DNS override")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('IPv6'), reason="no IPv6")
    def test_21_08_dnsd_aaaa(self, env: Env, httpd, dnsd):
        dnsd.set_answers(addr_aaaa=['[::1]'])
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        run_env['CURL_QUICK_EXIT'] = '1'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['remote_ip'] == '::1'

    # dnsd with one answer for A, delayed one for AAAA
    @pytest.mark.skipif(condition=not Env.curl_override_dns(), reason="no DNS override")
    def test_21_09_dnsd_a_delay(self, env: Env, httpd, dnsd):
        dnsd.set_answers(addr_a=['127.0.0.1'], addr_aaaa=['[::1]'],
                         delay_aaaa_ms=env.test_timeout * 1000)
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        run_env['CURL_QUICK_EXIT'] = '1'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['remote_ip'] == '127.0.0.1'

    # dnsd with one answer for AAAA, delayed one for A
    @pytest.mark.skipif(condition=not Env.curl_override_dns(), reason="no DNS override")
    @pytest.mark.skipif(condition=not Env.curl_has_feature('IPv6'), reason="no IPv6")
    def test_21_10_dnsd_aaaa_delay(self, env: Env, httpd, dnsd):
        dnsd.set_answers(addr_a=['127.0.0.1'], addr_aaaa=['[::1]'],
                         delay_a_ms=env.test_timeout * 1000)
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        run_env['CURL_QUICK_EXIT'] = '1'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], with_stats=True)
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        assert r.stats[0]['remote_ip'] == '::1'

    @pytest.mark.skip(reason="just test tests")
    def test_21_11_dnsd_parallel(self, env: Env, httpd, nghttpx, dnsd):
        count = 50
        dnsd.set_answers(addr_a=['127.0.0.1'], addr_aaaa=['[::1]'],
                         delay_aaaa_ms=501, delay_a_ms=10)
        run_env = os.environ.copy()
        run_env['CURL_DNS_SERVER'] = f'127.0.0.1:{dnsd.port}'
        curl = CurlClient(env=env, run_env=run_env, force_resolv=False)
        urls = [ f'https://test-{i}.{env.authority_for(env.domain1, "http/1.1")}' for i in range(count)]
        r = curl.http_download(urls=urls, with_stats=True, extra_args=[
            '--parallel', '--insecure'
        ])
        r.check_exit_code(0)
        r.check_stats(count=count, http_status=404)

    def _clean_files(self, files):
        for file in files:
            if os.path.exists(file):
                os.remove(file)
