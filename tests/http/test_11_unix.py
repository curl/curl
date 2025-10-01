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
import socket
import time
from threading import Thread
from typing import Generator

import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


class UDSFaker:

    def __init__(self, path, wait_sec=0):
        self._uds_path = path
        self._done = False
        self._socket = None
        self._thread = None
        self._wait_sec = wait_sec

    @property
    def path(self):
        return self._uds_path

    def start(self):
        self._done = False
        def process(self):
            self._socket.listen(1)
            self._process()

        try:
            os.unlink(self._uds_path)
        except OSError:
            if os.path.exists(self._uds_path):
                raise
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(self._uds_path)
        self._thread = Thread(target=process, daemon=True, args=[self])
        self._thread.start()

    def stop(self):
        self._done = True
        self._socket.close()

    def _process(self):
        while self._done is False:
            try:
                c, client_address = self._socket.accept()
                try:
                    c.recv(1024)
                    c.sendall("""HTTP/1.1 200 Ok
Server: UdsFaker
Content-Type: application/json
Content-Length: 19

{ "host": "faked" }""".encode())
                finally:
                    c.close()
                if self._wait_sec > 0:
                    time.sleep(self._wait_sec)
            except ConnectionAbortedError:
                self._done = True
            except OSError:
                self._done = True


class TestUnix:

    @pytest.fixture(scope="class")
    def uds_faker(self, env: Env) -> Generator[UDSFaker, None, None]:
        uds_path = os.path.join(env.gen_dir, 'uds_11.sock')
        faker = UDSFaker(path=uds_path, wait_sec=0)
        faker.start()
        yield faker
        faker.stop()

    @pytest.fixture(scope="class")
    def uds_faker2(self, env: Env) -> Generator[UDSFaker, None, None]:
        uds_path = os.path.join(env.gen_dir, 'uds_11_slow.sock')
        faker = UDSFaker(path=uds_path, wait_sec=1)
        faker.start()
        yield faker
        faker.stop()

    # download http: via Unix socket
    def test_11_01_unix_connect_http(self, env: Env, httpd, uds_faker):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(count=1, http_status=200)

    # download https: via Unix socket
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason="curl without SSL")
    def test_11_02_unix_connect_https(self, env: Env, httpd, uds_faker):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(exitcode=35, http_status=None)

    # download HTTP/3 via Unix socket
    @pytest.mark.skipif(condition=not Env.have_h3(), reason='h3 not supported')
    def test_11_03_unix_connect_quic(self, env: Env, httpd, uds_faker):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               alpn_proto='h3',
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(exitcode=96, http_status=None)

    # Run several connections against our UDS faker which is made to be really
    # slow. On macOS, the 3rd and 4th connect attempts have their sockets
    # closed due to the UDS accept queue being full. See #18748.
    # Check that curl keeps on trying and eventually all requests succeed.
    def test_11_04_unix_connect_block(self, env: Env, httpd, uds_faker2):
        run_env = os.environ.copy()
        run_env['CURL_FORBID_REUSE'] = '1'
        curl = CurlClient(env=env, run_env=run_env)
        count = 6
        urls = []
        xargs = ['-Z']
        for _ in range(count):
            urls.append('http://xxx.invalid/data.json')
            xargs.extend([
                '--unix-socket', uds_faker2.path,
                '--retry', '10',
                '--retry-connrefused',
                '--retry-delay', '1',
                '--retry-max-time', '3',
                '--connect-timeout', '3',
                '--max-time', '10',
            ])
        r = curl.http_download(urls=urls, with_stats=True, extra_args=xargs)
        # at least the 3 transfers should have succeeded
        successes = len([stat for stat in r.stats if stat['http_code'] == 200])
        assert successes >= 3, f'too few successes\n{r.dump_logs()}'
        # at least the last one timed out and did not produce a stat
        assert successes < count, f'none failed\n{r.dump_logs()}'
        # some should report CURLE_OPERATION_TIMEDOUT
        timeouts = len([stat for stat in r.stats if stat['exitcode'] in [7, 28]])
        assert timeouts > 0, f'none timed out?\n{r.dump_logs()}'

    # do test_11_04, but on a file that is no UDS. Needs to fail right away
    def test_11_05_unix_no_listener(self, env: Env, httpd):
        uds_none_path = os.path.join(env.gen_dir, 'uds_11_none.sock')
        open(uds_none_path, 'w')
        run_env = os.environ.copy()
        run_env['CURL_FORBID_REUSE'] = '1'
        curl = CurlClient(env=env, run_env=run_env)
        count = 6
        urls = []
        xargs = ['-Z']
        for _ in range(count):
            urls.append('http://xxx.invalid/data.json')
            xargs.extend([
                '--unix-socket', uds_none_path,
                '--connect-timeout', '3',
                '--max-time', '10',
            ])
        r = curl.http_download(urls=urls, with_stats=True, extra_args=xargs)
        r.check_exit_code(7)
        r.check_response(count=count, http_status=0)
        # all should report CURLE_COULDNT_CONNECT
        timeouts = len([stat for stat in r.stats if stat['exitcode'] == 7])
        assert timeouts == count, f'not all failed with 7\n{r.dump_logs()}'
