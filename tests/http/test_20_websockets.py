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
import shutil
import subprocess
import time
from datetime import datetime, timedelta
import pytest

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_protocol('ws'),
                    reason='curl lacks ws protocol support')
class TestWebsockets:

    def check_alive(self, env, timeout=5):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.ws_port}/'
        end = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end:
            r = curl.http_download(urls=[url])
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        return False

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    @pytest.fixture(autouse=True, scope='class')
    def ws_echo(self, env):
        run_dir = os.path.join(env.gen_dir, 'ws-echo-server')
        err_file = os.path.join(run_dir, 'stderr')
        self._rmrf(run_dir)
        self._mkpath(run_dir)

        with open(err_file, 'w') as cerr:
            cmd = os.path.join(env.project_dir,
                               'tests/http/testenv/ws_echo_server.py')
            args = [cmd, '--port', str(env.ws_port)]
            p = subprocess.Popen(args=args, cwd=run_dir, stderr=cerr,
                                 stdout=cerr)
            assert self.check_alive(env)
            yield
            p.terminate()

    def test_20_01_basic(self, env: Env, ws_echo, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.ws_port}/'
        r = curl.http_download(urls=[url])
        r.check_response(http_status=426)

    def test_20_02_pingpong_small(self, env: Env, ws_echo, repeat):
        payload = 125 * "x"
        client = LocalClient(env=env, name='ws-pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_03_pingpong_too_large(self, env: Env, ws_echo, repeat):
        payload = 127 * "x"
        client = LocalClient(env=env, name='ws-pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(56)

    # the python websocket server does not like 'large' control frames
    def test_20_04_data_small(self, env: Env, ws_echo, repeat):
        client = LocalClient(env=env, name='ws-data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, str(0), str(10)])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_05_data_med(self, env: Env, ws_echo, repeat):
        client = LocalClient(env=env, name='ws-data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, str(120), str(130)])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_06_data_large(self, env: Env, ws_echo, repeat):
        client = LocalClient(env=env, name='ws-data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, str(65535 - 5), str(65535 + 5)])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_07_data_large_small_recv(self, env: Env, ws_echo, repeat):
        client = LocalClient(env=env, name='ws-data', run_env={
            'CURL_WS_CHUNK_SIZE': '1024',
        })
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, str(65535 - 5), str(65535 + 5)])
        r.check_exit_code(0)
