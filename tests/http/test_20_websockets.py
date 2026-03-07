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
import socket
import subprocess
import time
from datetime import datetime, timedelta
from typing import Dict
import pytest

from testenv import Env, CurlClient, LocalClient
from testenv.ports import alloc_ports_and_do


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_protocol('ws'),
                    reason='curl lacks ws protocol support')
class TestWebsockets:

    PORT_SPECS = {
        'ws': socket.SOCK_STREAM,
    }

    def check_alive(self, env, port, timeout=Env.SERVER_TIMEOUT):
        curl = CurlClient(env=env)
        url = f'http://localhost:{port}/'
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
        self.run_dir = os.path.join(env.gen_dir, 'ws_echo_server')
        err_file = os.path.join(self.run_dir, 'stderr')
        self._rmrf(self.run_dir)
        self._mkpath(self.run_dir)
        self.cmd = os.path.join(env.project_dir,
                                'tests/http/testenv/ws_echo_server.py')
        self.wsproc = None
        self.cerr = None

        def startup(ports: Dict[str, int]) -> bool:
            wargs = [self.cmd, '--port', str(ports['ws'])]
            log.info(f'start_ {wargs}')
            self.wsproc = subprocess.Popen(args=wargs,
                                           cwd=self.run_dir,
                                           stderr=self.cerr,
                                           stdout=self.cerr)
            if self.check_alive(env, ports['ws']):
                env.update_ports(ports)
                return True
            log.error(f'not alive {wargs}')
            self.wsproc.terminate()
            self.wsproc = None
            return False

        with open(err_file, 'w') as self.cerr:
            assert alloc_ports_and_do(TestWebsockets.PORT_SPECS, startup,
                                      env.gen_root, max_tries=3)
            assert self.wsproc
            yield
            self.wsproc.terminate()

    def test_20_01_basic(self, env: Env, ws_echo):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.ws_port}/'
        r = curl.http_download(urls=[url])
        r.check_response(http_status=426)

    def test_20_02_pingpong_small(self, env: Env, ws_echo):
        payload = 125 * "x"
        client = LocalClient(env=env, name='cli_ws_pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_03_pingpong_too_large(self, env: Env, ws_echo):
        payload = 127 * "x"
        client = LocalClient(env=env, name='cli_ws_pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(100)  # CURLE_TOO_LARGE

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_04_data_small(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[f'-{model}', '-m', str(1), '-M', str(10), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_05_data_med(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[f'-{model}', '-m', str(120), '-M', str(130), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_06_data_large(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[f'-{model}', '-m', str(65535 - 5), '-M', str(65535 + 5), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_07_data_large_small_recv(self, env: Env, ws_echo, model):
        run_env = os.environ.copy()
        run_env['CURL_WS_CHUNK_SIZE'] = '1024'
        client = LocalClient(env=env, name='cli_ws_data', run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        r = client.run(args=[f'-{model}', '-m', str(65535 - 5), '-M', str(65535 + 5), url])
        r.check_exit_code(0)

    # Send large frames and simulate send blocking on 8192 bytes chunks
    # Simlates error reported in #15865
    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_08_data_very_large(self, env: Env, ws_echo, model):
        run_env = os.environ.copy()
        run_env['CURL_WS_CHUNK_EAGAIN'] = '8192'
        client = LocalClient(env=env, name='cli_ws_data', run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        count = 10
        large = 20000
        r = client.run(args=[f'-{model}', '-c', str(count), '-m', str(large), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_09_data_empty(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{env.ws_port}/'
        count = 10
        large = 0
        r = client.run(args=[f'-{model}', '-c', str(count), '-m', str(large), url])
        r.check_exit_code(0)
