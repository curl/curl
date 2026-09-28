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
from testenv import CurlClient, Env

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_feature('ECH'), reason="no curl ECH support")
@pytest.mark.skipif(condition=not Env.have_nghttpx_ech(), reason="no nghttpx ECH support")
@pytest.mark.skipif(condition=not Env.have_openssl_ech(), reason="no openssl cmd ECH support")
@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
class TestECH:

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'not configured', 0],
        ['hard', None, 35]  # CURLE_SSL_CONNECT_ERROR
    ])
    def test_23_01_ech_no_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode
        ])
        r.check_exit_code(exp_exit)
        if exp_exit == 0:
            r.check_stats(count=1, http_status=200, exitcode=0)
        if not env.curl_uses_lib('rustls-ffi') and not env.curl_uses_lib('wolfssl'):
            ech_result, _, _ = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'succeeded', 0],
        ['hard', 'succeeded', 0]
    ])
    def test_23_02_ech_good_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain1)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}'
        ])
        r.check_exit_code(exp_exit)
        if exp_exit == 0:
            r.check_stats(count=1, http_status=200, exitcode=0)
        if not env.curl_uses_lib('rustls-ffi') and not env.curl_uses_lib('wolfssl'):
            ech_result, inner, outer = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'
            if ech_result == 'succeeded':
                assert inner == env.domain1, f'{r.dump_logs()}'
                assert outer == env.domain1, f'{r.dump_logs()}'

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'rejected', 101],  # CURLE_ECH_REQUIRED
        ['hard', 'rejected', 101]
    ])
    def test_23_03_ech_bad_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain2)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}'
        ])
        if env.curl_uses_lib('wolfssl'):
            # wolfSSL fails the SNI check here: CURLE_PEER_FAILED_VERIFICATION
            # it also fails for GREASE mode, different from openssl and rustls
            r.check_exit_code(60 if exp_exit or ech_mode == 'grease' else 0)
        elif env.curl_uses_lib('rustls-ffi'):
            # rustls has no ECH error code when it fails
            # results in CURLE_SSL_CONNECT_ERROR
            r.check_exit_code(35 if exp_exit else 0)
        else:
            r.check_exit_code(exp_exit)
            ech_result, inner, outer = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'

    @pytest.mark.skipif(condition=Env.curl_uses_lib('rustls-ffi'),
                        reason="rustls has no ECH outer name support")
    @pytest.mark.skipif(condition=Env.curl_uses_lib('wolfssl'),
                        reason="wolfssl has no ECH outer name support")
    @pytest.mark.parametrize("ech_mode, exp_result, pub_domain", [
        ['true', 'succeeded', 'innocent.invalid'],
        ['hard', 'succeeded', 'innocent.invalid'],
    ])
    def test_23_04_ech_outer(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, pub_domain):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain1)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}', '--ech', f'pn:{pub_domain}'
        ])
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        ech_result, inner, outer = self._get_ech_result(r)
        assert ech_result == exp_result, f'{r.dump_logs()}'
        assert inner == env.domain1, f'{r.dump_logs()}'
        assert outer == pub_domain, f'{r.dump_logs()}'

    def _get_ech_result(self, r):
        for line in r.trace_lines:
            m = re.search(r'ECH: result \'(.+)\' \(inner=(.+), outer=(.+)\)', line)
            if m:
                return m.group(1), m.group(2), m.group(3)
            m = re.search(r'ECH: rejected(.*)', line)
            if m:
                return 'rejected', None, None
        return None, None, None
