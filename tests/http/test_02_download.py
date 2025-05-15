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
import logging
import math
import os
import re
import sys
from datetime import timedelta
import pytest

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestDownload:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=indir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=indir, fname="data-1m", fsize=1024*1024)
        env.make_data_file(indir=indir, fname="data-10m", fsize=10*1024*1024)
        env.make_data_file(indir=indir, fname="data-50m", fsize=50*1024*1024)
        env.make_data_gzipbomb(indir=indir, fname="bomb-100m.txt", fsize=100*1024*1024)

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_01_download_1(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(http_status=200)

    # download 2 files
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_02_download_2(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-1]'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(http_status=200, count=2)

    # download 100 files sequentially
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_03_download_sequential(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if (proto == 'http/1.1' or proto == 'h2') and env.curl_uses_lib('mbedtls') and \
           sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('mbedtls 3.6.3 fails this test on macOS CI runners')
        count = 10
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(http_status=200, count=count, connect_count=1)

    # download 100 files parallel
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_04_download_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h2' and env.curl_uses_lib('mbedtls') and \
           sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('mbedtls 3.6.3 fails this test on macOS CI runners')
        count = 10
        max_parallel = 5
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel', '--parallel-max', f'{max_parallel}'
        ])
        r.check_response(http_status=200, count=count)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1, r.dump_logs()
        else:
            # http2 parallel transfers will use one connection (common limit is 100)
            assert r.total_connects == 1, r.dump_logs()

    # download 500 files sequential
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_05_download_many_sequential(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 shaky here")
        if proto == 'h2' and env.curl_uses_lib('mbedtls') and \
           sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('mbedtls 3.6.3 fails this test on macOS CI runners')
        count = 200
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(http_status=200, count=count)
        if proto == 'http/1.1':
            # http/1.1 parallel transfers will open multiple connections
            assert r.total_connects > 1, r.dump_logs()
        else:
            # http2 parallel transfers will use one connection (common limit is 100)
            assert r.total_connects == 1, r.dump_logs()

    # download 500 files parallel
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_06_download_many_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h2' and env.curl_uses_lib('mbedtls') and \
           sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('mbedtls 3.6.3 fails this test on macOS CI runners')
        count = 200
        max_parallel = 50
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[000-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel', '--parallel-max', f'{max_parallel}'
        ])
        r.check_response(http_status=200, count=count, connect_count=1)

    # download files parallel, check connection reuse/multiplex
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_07_download_reuse(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 200
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto,
                               with_stats=True, extra_args=[
            '--parallel', '--parallel-max', '200'
        ])
        r.check_response(http_status=200, count=count)
        # should have used at most 2 connections only (test servers allow 100 req/conn)
        # it may be just 1 on slow systems where request are answered faster than
        # curl can exhaust the capacity or if curl runs with address-sanitizer speed
        assert r.total_connects <= 2, "h2 should use fewer connections here"

    # download files parallel with http/1.1, check connection not reused
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_02_07b_download_reuse(self, env: Env, httpd, nghttpx, proto):
        count = 6
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto,
                               with_stats=True, extra_args=[
            '--parallel'
        ])
        r.check_response(count=count, http_status=200)
        # http/1.1 should have used count connections
        assert r.total_connects == count, "http/1.1 should use this many connections"

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_08_1MB_serial(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 5
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-1m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200)

    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_09_1MB_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 5
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-1m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        r.check_response(count=count, http_status=200)

    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_10_10MB_serial(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 3
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-10m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=count, http_status=200)

    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    @pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_11_10MB_parallel(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        count = 3
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-10m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        r.check_response(count=count, http_status=200)

    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_12_head_serial_https(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 5
        urln = f'https://{env.authority_for(env.domain1, proto)}/data-10m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--head'
        ])
        r.check_response(count=count, http_status=200)

    @pytest.mark.parametrize("proto", ['h2'])
    def test_02_13_head_serial_h2c(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 5
        urln = f'http://{env.domain1}:{env.http_port}/data-10m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--head', '--http2-prior-knowledge', '--fail-early'
        ])
        r.check_response(count=count, http_status=200)

    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_14_not_found(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        count = 5
        urln = f'https://{env.authority_for(env.domain1, proto)}/not-found?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--parallel'
        ])
        r.check_stats(count=count, http_status=404, exitcode=0,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')

    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_02_15_fail_not_found(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_lib('msh3'):
            pytest.skip("msh3 stalls here")
        count = 5
        urln = f'https://{env.authority_for(env.domain1, proto)}/not-found?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--fail'
        ])
        r.check_stats(count=count, http_status=404, exitcode=22,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')

    @pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
    def test_02_20_h2_small_frames(self, env: Env, httpd, configures_httpd):
        # Test case to reproduce content corruption as observed in
        # https://github.com/curl/curl/issues/10525
        # To reliably reproduce, we need an Apache httpd that supports
        # setting smaller frame sizes. This is not released yet, we
        # test if it works and back out if not.
        httpd.set_extra_config(env.domain1, lines=[
            'H2MaxDataFrameLen 1024',
        ])
        if not httpd.reload_if_config_changed():
            pytest.skip('H2MaxDataFrameLen not supported')
        # ok, make 100 downloads with 2 parallel running and they
        # are expected to stumble into the issue when using `lib/http2.c`
        # from curl 7.88.0
        count = 5
        urln = f'https://{env.authority_for(env.domain1, "h2")}/data-1m?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto="h2", extra_args=[
            '--parallel', '--parallel-max', '2'
        ])
        r.check_response(count=count, http_status=200)
        srcfile = os.path.join(httpd.docs_dir, 'data-1m')
        self.check_downloads(curl, srcfile, count)

    # download serial via lib client, pause/resume at different offsets
    @pytest.mark.parametrize("pause_offset", [0, 10*1024, 100*1023, 640000])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h3'])
    def test_02_21_lib_serial(self, env: Env, httpd, nghttpx, proto, pause_offset):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        docname = 'data-10m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)

    # h2 download parallel via lib client, pause/resume at different offsets
    # debug-override stream window size to reproduce #16955
    @pytest.mark.parametrize("pause_offset", [0, 10*1024, 100*1023, 640000])
    @pytest.mark.parametrize("swin_max", [0, 10*1024])
    def test_02_21_h2_lib_serial(self, env: Env, httpd, pause_offset, swin_max):
        proto = 'h2'
        count = 2
        docname = 'data-10m'
        url = f'https://localhost:{env.https_port}/{docname}'
        run_env = os.environ.copy()
        run_env['CURL_DEBUG'] = 'multi,http/2'
        if swin_max > 0:
            run_env['CURL_H2_STREAM_WIN_MAX'] = f'{swin_max}'
        client = LocalClient(name='hx-download', env=env, run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)

    # download via lib client, several at a time, pause/resume
    @pytest.mark.parametrize("pause_offset", [100*1023])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_22_lib_parallel_resume(self, env: Env, httpd, nghttpx, proto, pause_offset):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        max_parallel = 5
        docname = 'data-10m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
            '-n', f'{count}', '-m', f'{max_parallel}',
            '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)

    # download, several at a time, pause and abort paused
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_23a_lib_abort_paused(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_ossl_quic():
            pytest.skip('OpenSSL QUIC fails here')
        if proto == 'h3' and env.ci_run and env.curl_uses_lib('quiche'):
            pytest.skip("fails in CI, but works locally for unknown reasons")
        count = 10
        max_parallel = 5
        if proto in ['h2', 'h3']:
            pause_offset = 64 * 1024
        else:
            pause_offset = 12 * 1024
        docname = 'data-1m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
            '-n', f'{count}', '-m', f'{max_parallel}', '-a',
            '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        # downloads should be there, but not necessarily complete
        self.check_downloads(client, srcfile, count, complete=False)

    # download, several at a time, abort after n bytes
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_23b_lib_abort_offset(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_ossl_quic():
            pytest.skip('OpenSSL QUIC fails here')
        if proto == 'h3' and env.ci_run and env.curl_uses_lib('quiche'):
            pytest.skip("fails in CI, but works locally for unknown reasons")
        count = 10
        max_parallel = 5
        if proto in ['h2', 'h3']:
            abort_offset = 64 * 1024
        else:
            abort_offset = 12 * 1024
        docname = 'data-1m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
            '-n', f'{count}', '-m', f'{max_parallel}', '-a',
            '-A', f'{abort_offset}', '-V', proto, url
        ])
        r.check_exit_code(42)  # CURLE_ABORTED_BY_CALLBACK
        srcfile = os.path.join(httpd.docs_dir, docname)
        # downloads should be there, but not necessarily complete
        self.check_downloads(client, srcfile, count, complete=False)

    # download, several at a time, abort after n bytes
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_23c_lib_fail_offset(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        if proto == 'h3' and env.curl_uses_ossl_quic():
            pytest.skip('OpenSSL QUIC fails here')
        if proto == 'h3' and env.ci_run and env.curl_uses_lib('quiche'):
            pytest.skip("fails in CI, but works locally for unknown reasons")
        count = 10
        max_parallel = 5
        if proto in ['h2', 'h3']:
            fail_offset = 64 * 1024
        else:
            fail_offset = 12 * 1024
        docname = 'data-1m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
            '-n', f'{count}', '-m', f'{max_parallel}', '-a',
            '-F', f'{fail_offset}', '-V', proto, url
        ])
        r.check_exit_code(23)  # CURLE_WRITE_ERROR
        srcfile = os.path.join(httpd.docs_dir, docname)
        # downloads should be there, but not necessarily complete
        self.check_downloads(client, srcfile, count, complete=False)

    # speed limited download
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_24_speed_limit(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        url = f'https://{env.authority_for(env.domain1, proto)}/data-1m'
        curl = CurlClient(env=env)
        speed_limit = 384 * 1024
        min_duration = math.floor((1024 * 1024)/speed_limit)
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--limit-rate', f'{speed_limit}'
        ])
        r.check_response(count=count, http_status=200)
        assert r.duration > timedelta(seconds=min_duration), \
            f'rate limited transfer should take more than {min_duration}s, '\
            f'not {r.duration}'

    # make extreme parallel h2 upgrades, check invalid conn reuse
    # before protocol switch has happened
    def test_02_25_h2_upgrade_x(self, env: Env, httpd):
        url = f'http://localhost:{env.http_port}/data-100k'
        client = LocalClient(name='h2-upgrade-extreme', env=env, timeout=15)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[url])
        assert r.exit_code == 0, f'{client.dump_logs()}'

    # Special client that tests TLS session reuse in parallel transfers
    # TODO: just uses a single connection for h2/h3. Not sure how to prevent that
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_26_session_shared_reuse(self, env: Env, proto, httpd, nghttpx):
        url = f'https://{env.authority_for(env.domain1, proto)}/data-100k'
        client = LocalClient(name='tls-session-reuse', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[proto, url])
        r.check_exit_code(0)

    # test on paused transfers, based on issue #11982
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_27a_paused_no_cl(self, env: Env, httpd, nghttpx, proto):
        url = f'https://{env.authority_for(env.domain1, proto)}' \
            '/curltest/tweak/?&chunks=6&chunk_size=8000'
        client = LocalClient(env=env, name='h2-pausing')
        r = client.run(args=['-V', proto, url])
        r.check_exit_code(0)

    # test on paused transfers, based on issue #11982
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_27b_paused_no_cl(self, env: Env, httpd, nghttpx, proto):
        url = f'https://{env.authority_for(env.domain1, proto)}' \
            '/curltest/tweak/?error=502'
        client = LocalClient(env=env, name='h2-pausing')
        r = client.run(args=['-V', proto, url])
        r.check_exit_code(0)

    # test on paused transfers, based on issue #11982
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_27c_paused_no_cl(self, env: Env, httpd, nghttpx, proto):
        url = f'https://{env.authority_for(env.domain1, proto)}' \
            '/curltest/tweak/?status=200&chunks=1&chunk_size=100'
        client = LocalClient(env=env, name='h2-pausing')
        r = client.run(args=['-V', proto, url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_28_get_compressed(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        urln = f'https://{env.authority_for(env.domain1brotli, proto)}/data-100k?[0-{count-1}]'
        curl = CurlClient(env=env)
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--compressed'
        ])
        r.check_exit_code(code=0)
        r.check_response(count=count, http_status=200)

    def check_downloads(self, client, srcfile: str, count: int,
                        complete: bool = True):
        for i in range(count):
            dfile = client.download_file(i)
            assert os.path.exists(dfile)
            if complete and not filecmp.cmp(srcfile, dfile, shallow=False):
                diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                    b=open(dfile).readlines(),
                                                    fromfile=srcfile,
                                                    tofile=dfile,
                                                    n=1))
                assert False, f'download {dfile} differs:\n{diff}'

    # download via lib client, 1 at a time, pause/resume at different offsets
    @pytest.mark.parametrize("pause_offset", [0, 10*1024, 100*1023, 640000])
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_29_h2_lib_serial(self, env: Env, httpd, nghttpx, proto, pause_offset):
        count = 2
        docname = 'data-10m'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)

    # download parallel with prior knowledge
    def test_02_30_parallel_prior_knowledge(self, env: Env, httpd):
        count = 3
        curl = CurlClient(env=env)
        urln = f'http://{env.domain1}:{env.http_port}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], extra_args=[
            '--parallel', '--http2-prior-knowledge'
        ])
        r.check_response(http_status=200, count=count)
        assert r.total_connects == 1, r.dump_logs()

    # download parallel with h2 "Upgrade:"
    def test_02_31_parallel_upgrade(self, env: Env, httpd, nghttpx):
        count = 3
        curl = CurlClient(env=env)
        urln = f'http://{env.domain1}:{env.http_port}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], extra_args=[
            '--parallel', '--http2'
        ])
        r.check_response(http_status=200, count=count)
        # we see up to 3 connections, because Apache wants to serve only a single
        # request via Upgrade: and then closes the connection. But if a new
        # request comes in time, it might still get served.
        assert r.total_connects <= 3, r.dump_logs()

    # nghttpx is the only server we have that supports TLS early data
    @pytest.mark.skipif(condition=not Env.have_nghttpx(), reason="no nghttpx")
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_32_earlydata(self, env: Env, httpd, nghttpx, proto):
        if not env.curl_can_early_data():
            pytest.skip('TLS earlydata not implemented')
        if proto == 'h3' and \
           (not env.have_h3() or not env.curl_can_h3_early_data()):
            pytest.skip("h3 not supported")
        if proto != 'h3' and sys.platform.startswith('darwin') and env.ci_run:
            pytest.skip('failing on macOS CI runners')
        count = 2
        docname = 'data-10k'
        # we want this test to always connect to nghttpx, since it is
        # the only server we have that supports TLS earlydata
        port = env.port_for(proto)
        if proto != 'h3':
            port = env.nghttpx_https_port
        url = f'https://{env.domain1}:{port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-e',  # use TLS earlydata
             '-f',  # forbid reuse of connections
             '-r', f'{env.domain1}:{port}:127.0.0.1',
             '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)
        # check that TLS earlydata worked as expected
        earlydata = {}
        reused_session = False
        for line in r.trace_lines:
            m = re.match(r'^\[t-(\d+)] EarlyData: (-?\d+)', line)
            if m:
                earlydata[int(m.group(1))] = int(m.group(2))
                continue
            m = re.match(r'\[1-1] \* SSL reusing session.*', line)
            if m:
                reused_session = True
        assert reused_session, 'session was not reused for 2nd transfer'
        assert earlydata[0] == 0, f'{earlydata}'
        if proto == 'http/1.1':
            assert earlydata[1] == 111, f'{earlydata}'
        elif proto == 'h2':
            assert earlydata[1] == 127, f'{earlydata}'
        elif proto == 'h3':
            assert earlydata[1] == 109, f'{earlydata}'

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("max_host_conns", [0, 1, 5])
    def test_02_33_max_host_conns(self, env: Env, httpd, nghttpx, proto, max_host_conns):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        max_parallel = 50
        docname = 'data-10k'
        port = env.port_for(proto)
        url = f'https://{env.domain1}:{port}/{docname}'
        run_env = os.environ.copy()
        run_env['CURL_DEBUG'] = 'multi'
        client = LocalClient(name='hx-download', env=env, run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-m', f'{max_parallel}',
             '-x',  # always use a fresh connection
             '-M',  str(max_host_conns),  # limit conns per host
             '-r', f'{env.domain1}:{port}:127.0.0.1',
             '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)
        if max_host_conns > 0:
            matched_lines = 0
            for line in r.trace_lines:
                m = re.match(r'.*The cache now contains (\d+) members.*', line)
                if m:
                    matched_lines += 1
                    n = int(m.group(1))
                    assert n <= max_host_conns
            assert matched_lines > 0

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2'])
    @pytest.mark.parametrize("max_total_conns", [0, 1, 5])
    def test_02_34_max_total_conns(self, env: Env, httpd, nghttpx, proto, max_total_conns):
        if not env.curl_is_debug():
            pytest.skip('only works for curl debug builds')
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        max_parallel = 50
        docname = 'data-10k'
        port = env.port_for(proto)
        url = f'https://{env.domain1}:{port}/{docname}'
        run_env = os.environ.copy()
        run_env['CURL_DEBUG'] = 'multi'
        client = LocalClient(name='hx-download', env=env, run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}',
             '-m', f'{max_parallel}',
             '-x',  # always use a fresh connection
             '-T',  str(max_total_conns),  # limit total connections
             '-r', f'{env.domain1}:{port}:127.0.0.1',
             '-V', proto, url
        ])
        r.check_exit_code(0)
        srcfile = os.path.join(httpd.docs_dir, docname)
        self.check_downloads(client, srcfile, count)
        if max_total_conns > 0:
            matched_lines = 0
            for line in r.trace_lines:
                m = re.match(r'.*The cache now contains (\d+) members.*', line)
                if m:
                    matched_lines += 1
                    n = int(m.group(1))
                    assert n <= max_total_conns
            assert matched_lines > 0

    # 2 parallel transers, pause and resume. Load a 100 MB zip bomb from
    # the server with "Content-Encoding: gzip" that gets exloded during
    # response writing to the client. Client pauses after 1MB unzipped data
    # and causes buffers to fill while the server sends more response
    # data.
    # * http/1.1: not much buffering is done as curl does no longer
    #   serve the connections that are paused
    # * h2/h3: server continues sending what the stream window allows and
    #   since the one connection involved unpaused transfers, data continues
    #   to be received, requiring buffering.
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_02_35_pause_bomb(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        pause_offset = 1024 * 1024
        docname = 'bomb-100m.txt.var'
        url = f'https://localhost:{env.https_port}/{docname}'
        client = LocalClient(name='hx-download', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[
             '-n', f'{count}', '-m', f'{count}',
             '-P', f'{pause_offset}', '-V', proto, url
        ])
        r.check_exit_code(0)
