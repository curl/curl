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
from threading import Thread
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)

class UDSFaker:

    def __init__(self, path):
        self._uds_path = path
        self._done = False

    @property
    def path(self):
        return self._uds_path

    def start(self):
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
                    data = c.recv(16)
                    c.sendall("""HTTP/1.1 200 Ok
Server: UdsFaker
Content-Type: application/json
Content-Length: 19

{ "host": "faked" }""".encode())
                finally:
                    c.close()

            except ConnectionAbortedError:
                self._done = True
            except OSError:
                self._done = True


class TestUnix:

    @pytest.fixture(scope="class")
    def uds_faker(self, env: Env) -> UDSFaker:
        uds_path = os.path.join(env.gen_dir, 'uds_11.sock')
        faker = UDSFaker(path=uds_path)
        faker.start()
        yield faker
        faker.stop()

    # download http: via unix socket
    def test_11_01_unix_connect_http(self, env: Env, httpd, uds_faker, repeat):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(count=1, http_status=200)

    # download https: via unix socket
    @pytest.mark.skipif(condition=not Env.have_ssl_curl(), reason=f"curl without SSL")
    def test_11_02_unix_connect_http(self, env: Env, httpd, uds_faker, repeat):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(exitcode=35, http_status=None)

    # download HTTP/3 via unix socket
    @pytest.mark.skipif(condition=not Env.have_h3(), reason='h3 not supported')
    def test_11_03_unix_connect_quic(self, env: Env, httpd, uds_faker, repeat):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True,
                               alpn_proto='h3',
                               extra_args=[
                                 '--unix-socket', uds_faker.path,
                               ])
        r.check_response(exitcode=96, http_status=None)
