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
import subprocess
import time
from datetime import timedelta, datetime

from typing import Dict

from . import CurlClient
from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Dante:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.danted
        self._port = 0
        self.name = 'danted'
        self._port_skey = 'danted'
        self._port_specs = {
            'danted': socket.SOCK_STREAM,
        }
        self._dante_dir = os.path.join(env.gen_dir, self.name)
        self._run_dir = os.path.join(self._dante_dir, 'run')
        self._tmp_dir = os.path.join(self._dante_dir, 'tmp')
        self._conf_file = os.path.join(self._dante_dir, 'test.conf')
        self._dante_log = os.path.join(self._dante_dir, 'dante.log')
        self._error_log = os.path.join(self._dante_dir, 'error.log')
        self._pid_file = os.path.join(self._dante_dir, 'dante.pid')
        self._process = None

        self.clear_logs()

    @property
    def port(self) -> int:
        return self._port

    def clear_logs(self):
        self._rmf(self._error_log)
        self._rmf(self._dante_log)

    def exists(self):
        return os.path.exists(self._cmd)

    def is_running(self):
        if self._process:
            self._process.poll()
            return self._process.returncode is None
        return False

    def start_if_needed(self):
        if not self.is_running():
            return self.start()
        return True

    def stop(self, wait_dead=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self._process.terminate()
            self._process.wait(timeout=2)
            self._process = None
            return not wait_dead or True
        return True

    def restart(self):
        self.stop()
        return self.start()

    def initial_start(self):

        def startup(ports: Dict[str, int]) -> bool:
            self._port = ports[self._port_skey]
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._port = 0
            return False

        return alloc_ports_and_do(self._port_specs, startup,
                                  self.env.gen_root, max_tries=3)

    def start(self, wait_live=True):
        assert self._port > 0
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        self._write_config()
        args = [
            self._cmd,
            '-f', f'{self._conf_file}',
            '-p', f'{self._pid_file}',
            '-d', '0',
        ]
        procerr = open(self._error_log, 'a')
        self._process = subprocess.Popen(args=args, stderr=procerr)
        if self._process.returncode is not None:
            return False
        return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir,
                          timeout=timeout.total_seconds(), socks_args=[
            '--socks5', f'127.0.0.1:{self._port}'
        ])
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'http://{self.env.domain1}:{self.env.http_port}/')
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        log.error(f"Server still not responding after {timeout}")
        return False

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _write_config(self):
        conf = [
            f'errorlog: {self._error_log}',
            f'logoutput: {self._dante_log}',
            f'internal: 127.0.0.1 port = {self._port}',
            'external: 127.0.0.1',
            'clientmethod: none',
            'socksmethod: none',
            'client pass {',
            '  from: 127.0.0.0/24 to: 0.0.0.0/0',
            '  log: error',
            '}',
            'socks pass {',
            '  from: 0.0.0.0/0 to: 0.0.0.0/0',
            '  command: bindreply connect udpreply',
            '  log: error',
            '}',
            '\n',
        ]
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join(conf))
