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
from json import JSONEncoder
from typing import Dict

from .curl import CurlClient
from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Caddy:

    PORT_SPECS = {
        'caddy': socket.SOCK_STREAM,
        'caddys': socket.SOCK_STREAM,
    }

    def __init__(self, env: Env):
        self.env = env
        self._caddy = os.environ['CADDY'] if 'CADDY' in os.environ else env.caddy
        self._caddy_dir = os.path.join(env.gen_dir, 'caddy')
        self._docs_dir = os.path.join(self._caddy_dir, 'docs')
        self._conf_file = os.path.join(self._caddy_dir, 'Caddyfile')
        self._error_log = os.path.join(self._caddy_dir, 'caddy.log')
        self._tmp_dir = os.path.join(self._caddy_dir, 'tmp')
        self._process = None
        self._http_port = 0
        self._https_port = 0
        self._rmf(self._error_log)

    @property
    def docs_dir(self):
        return self._docs_dir

    @property
    def port(self) -> int:
        return self._https_port

    def clear_logs(self):
        self._rmf(self._error_log)

    def is_running(self):
        if self._process:
            self._process.poll()
            return self._process.returncode is None
        return False

    def start_if_needed(self):
        if not self.is_running():
            return self.start()
        return True

    def initial_start(self):

        def startup(ports: Dict[str, int]) -> bool:
            self._http_port = ports['caddy']
            self._https_port = ports['caddys']
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._http_port = 0
            self._https_port = 0
            return False

        return alloc_ports_and_do(Caddy.PORT_SPECS, startup,
                                  self.env.gen_root, max_tries=3)

    def start(self, wait_live=True):
        assert self._http_port > 0 and self._https_port > 0
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        self._write_config()
        args = [
            self._caddy, 'run'
        ]
        caddyerr = open(self._error_log, 'a')
        self._process = subprocess.Popen(args=args, cwd=self._caddy_dir, stderr=caddyerr)
        if self._process.returncode is not None:
            return False
        return not wait_live or self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def stop(self, wait_dead=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self._process.terminate()
            self._process.wait(timeout=2)
            self._process = None
            return not wait_dead or self.wait_dead(timeout=timedelta(seconds=5))
        return True

    def restart(self):
        self.stop()
        return self.start()

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'https://{self.env.domain1}:{self.port}/'
            r = curl.http_get(url=check_url)
            if r.exit_code != 0:
                return True
            log.debug(f'waiting for caddy to stop responding: {r}')
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'https://{self.env.domain1}:{self.port}/'
            r = curl.http_get(url=check_url)
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        log.error(f"Caddy still not responding after {timeout}")
        return False

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _write_config(self):
        domain1 = self.env.domain1
        creds1 = self.env.get_credentials(domain1)
        assert creds1  # convince pytype this isn't None
        domain2 = self.env.domain2
        creds2 = self.env.get_credentials(domain2)
        assert creds2  # convince pytype this isn't None
        self._mkpath(self._docs_dir)
        self._mkpath(self._tmp_dir)
        with open(os.path.join(self._docs_dir, 'data.json'), 'w') as fd:
            data = {
                'server': f'{domain1}',
            }
            fd.write(JSONEncoder().encode(data))
        with open(self._conf_file, 'w') as fd:
            conf = [   # base server config
                '{',
                f'  http_port {self._http_port}',
                f'  https_port {self._https_port}',
                '  log default {',
                '     level ERROR',
                '}',
                f'  servers :{self._https_port} {{',
                '    protocols h3 h2 h1',
                '  }',
                '}',
                f'{domain1}:{self._https_port} {{',
                '  file_server * {',
                f'    root {self._docs_dir}',
                '  }',
                f'  tls {creds1.cert_file} {creds1.pkey_file}',
                '}',
            ]
            if self.env.http_port > 0:
                conf.extend([
                    f'{domain2} {{',
                    f'  reverse_proxy /* http://localhost:{self.env.http_port} {{',
                    '  }',
                    f'  tls {creds2.cert_file} {creds2.pkey_file}',
                    '}',
                ])
            fd.write("\n".join(conf))
