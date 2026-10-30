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
import re

import pytest
from testenv import CurlClient, Env, LocalClient

log = logging.getLogger(__name__)


class TestPriority:
    """RFC 9218 request priorities, the Priority header and PRIORITY_UPDATE."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env, httpd, nghttpx):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-1m", fsize=1024 * 1024)

    @staticmethod
    def _priority_hd_lines(r, proto: str):
        pat = re.compile(r'.*\[HTTP/[23]\] \[\d+\] \[priority: (.*)\]')
        return [m.group(1) for m in (pat.match(line) for line in r.trace_lines) if m]

    # the Priority header is sent over h2
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason='needs curl verbose strings')
    @pytest.mark.skipif(condition=not Env.have_h2_curl(), reason="curl without h2")
    def test_25_01_header_h2(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='h2',
                               extra_args=['--priority', 'u=1, i'])
        r.check_response(count=1, http_status=200)
        assert self._priority_hd_lines(r, 'h2') == ['u=1, i'], f'{r.trace_lines}'

    # urgency only and incremental only
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason='needs curl verbose strings')
    @pytest.mark.skipif(condition=not Env.have_h2_curl(), reason="curl without h2")
    @pytest.mark.parametrize("value,expected", [
        pytest.param('u=0', 'u=0', id='urgency'),
        pytest.param('i', 'i', id='incremental'),
        pytest.param('i,u=7', 'u=7, i', id='both-reordered'),
        pytest.param('u=2, i=?1', 'u=2, i', id='boolean-true'),
        pytest.param('u=2, i=?0', 'u=2', id='boolean-false'),
        pytest.param('u=1, x=2, i', 'u=1, i', id='unknown-member'),
        pytest.param('u=1;foo=bar, i;baz', 'u=1, i', id='parameters'),
        pytest.param('u=5, y', 'u=5', id='unknown-boolean'),
    ])
    def test_25_02_header_values(self, env: Env, httpd, value, expected):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='h2',
                               extra_args=['--priority', value])
        r.check_response(count=1, http_status=200)
        assert self._priority_hd_lines(r, 'h2') == [expected], f'{r.trace_lines}'

    # the Priority header is not sent over http/1.1
    def test_25_03_no_header_h1(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "http/1.1")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1',
                               extra_args=['--priority', 'u=1, i'])
        r.check_response(count=1, http_status=200)
        pat = re.compile(r'.*priority: u=', re.IGNORECASE)
        assert not [line for line in r.trace_lines if pat.match(line)], f'{r.trace_lines}'

    # a Priority header given by the user wins
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason='needs curl verbose strings')
    @pytest.mark.skipif(condition=not Env.have_h2_curl(), reason="curl without h2")
    def test_25_03b_user_header(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='h2',
                               extra_args=['--priority', 'u=1, i',
                                           '-H', 'Priority: u=0'])
        r.check_response(count=1, http_status=200)
        assert self._priority_hd_lines(r, 'h2') == ['u=0'], f'{r.trace_lines}'

    # invalid values are rejected by the tool
    @pytest.mark.parametrize("value", [
        'u=8', 'u=', 'u', 'u=10', 'u=1 i', 'u=1,,i', '', 'I', 'U=1', 'i=?2',
        'i=1', '=1', ',u=1'
    ])
    def test_25_04_invalid_values(self, env: Env, httpd, value):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h2")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='h2',
                               extra_args=['--priority', value])
        r.check_exit_code(2)

    # the Priority header is sent over h3
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason='needs curl verbose strings')
    @pytest.mark.skipif(condition=not Env.have_h3(), reason="h3 not supported")
    def test_25_05_header_h3(self, env: Env, httpd, nghttpx):
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='h3',
                               extra_args=['--priority', 'u=2'])
        r.check_response(count=1, http_status=200)
        assert self._priority_hd_lines(r, 'h3') == ['u=2'], f'{r.trace_lines}'

    # changing the priority during a transfer sends a PRIORITY_UPDATE
    @pytest.mark.skipif(condition=not Env.curl_is_verbose(), reason='needs curl verbose strings')
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_25_06_reprioritize(self, env: Env, httpd, nghttpx, nghttpx_tcp,
                                proto):
        # nghttpx announces support for RFC 9218 over h2 and serves h3
        if proto == 'h3':
            if not env.have_h3() or not nghttpx:
                pytest.skip("h3 not supported")
            port = env.h3_port
        else:
            if not env.have_h2_curl():
                pytest.skip("curl without h2")
            if not nghttpx_tcp:
                pytest.skip("nghttpx not available")
            port = nghttpx_tcp.port
        client = LocalClient(name='cli_hx_download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'https://{env.domain1}:{port}/data-1m'
        # start with "u=6, i" and switch to urgency 0 on the first data
        r = client.run(args=['-V', proto, '-C', env.ca.cert_file,
                             '-r', f'{env.domain1}:{port}:127.0.0.1',
                             '-U', '6', '-I', '-u', '0', url])
        r.check_exit_code(0)
        assert self._priority_hd_lines(r, proto) == ['u=6, i'], f'{r.trace_lines}'
        updates = [line for line in r.trace_lines if "PRIORITY_UPDATE '" in line]
        assert len(updates) == 1, f'{r.trace_lines}'
        assert "'u=0'" in updates[0], f'{updates}'
        if proto == 'h2':
            # the frame actually went out
            sent = [line for line in r.trace_lines
                    if re.match(r'.*-> FRAME\[PRIORITY_UPDATE', line)]
            assert len(sent) == 1, f'{r.trace_lines}'
