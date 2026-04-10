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
from datetime import datetime, timedelta
from typing import Dict, List

from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Dnsd:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = os.path.join(env.build_dir, 'tests/server/servers')
        self._port = 0
        self.name = 'dnsd'
        self._port_skey = 'dnsd'
        self._port_specs = {
            'dnsd': socket.SOCK_DGRAM,
        }
        self._dnsd_dir = os.path.join(env.gen_dir, self.name)
        self._log_dir = self._dnsd_dir
        self._lock_dir = os.path.join(self._dnsd_dir, 'lock')
        self._log_file = os.path.join(self._log_dir, 'dnsd.log')
        self._conf_file = os.path.join(self._log_dir, 'dnsd.cmd')
        self._pid_file = os.path.join(self._log_dir, 'dante.pid')
        self._error_log = os.path.join(self._log_dir, 'dnsd.err.log')
        self._process = None

        self.clear_logs()

    @property
    def port(self) -> int:
        return self._port

    def clear_logs(self):
        self._rmf(self._log_file)
        self._rmf(self._error_log)

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
        self._mkpath(self._lock_dir)

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
        if self._process:
            self.stop()
        self.set_answers()  # empty answers by default
        self._rmf(self._log_file)
        args = [
            self._cmd, 'dnsd',
            '--port', str(self._port),
            '--logdir', f'{self._log_dir}',
            '--logfile', f'{self._log_file}',
            '--pidfile', f'{self._pid_file}',
        ]
        procerr = open(self._error_log, 'a')
        self._process = subprocess.Popen(args=args, stderr=procerr)
        if self._process.returncode is not None:
            return False
        return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def wait_live(self, timeout: timedelta):
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            if os.path.exists(self._log_file):
                return True
            time.sleep(.1)
        log.error(f"Server still not responding after {timeout}")
        return False

    def _rmf(self, path):
        if os.path.exists(path):
            os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def set_answers(self, addr_a: List[str] = None,
                    addr_aaaa: List[str] = None):
        conf = []
        if addr_a:
            conf.extend([f'A: {addr}' for addr in addr_a])
        if addr_aaaa:
            conf.extend([f'AAAA: {addr}' for addr in addr_aaaa])
        conf.append('\n')
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join(conf))
