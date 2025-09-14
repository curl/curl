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
import signal
import socket
import subprocess
import time
from typing import Optional, Dict
from datetime import datetime, timedelta

from .env import Env
from .curl import CurlClient
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class H2o:
    def __init__(self, env: Env, name: str, domain: str, cred_name: str):
        self.env = env
        self._name = name
        self._domain = domain
        self._port = 0 # defaults to h3_port
        self._cred_name = cred_name
        self._loaded_cred_name = None
        self._process = None
        self._tmp_dir = os.path.join(self.env.gen_dir, self._name)
        self._run_dir = os.path.join(self._tmp_dir, 'run')
        self._conf_file = os.path.join(self._run_dir, 'h2o.conf')
        self._error_log = os.path.join(self._run_dir, 'h2o.log')
        self._pid_file = os.path.join(self._run_dir, 'h2o.pid')
        self._stderr = os.path.join(self._run_dir, 'h2o.stderr')
        self._cmd = env.CONFIG.h2o
        # For proxy subclasses
        self._h1_port = None
        self._h2_port = None

    @property
    def port(self) -> int:
        return self._port

    @property
    def h1_port(self) -> Optional[int]:
        return getattr(self, '_h1_port', None)

    @property
    def h2_port(self) -> Optional[int]:
        return getattr(self, '_h2_port', None)

    def clear_logs(self):
        self._rmf(self._error_log)
        self._rmf(self._stderr)

    def dump_logs(self):
        lines = []
        lines.append(f'stderr of {self._name}')
        lines.append('-------------------------------------------')
        self._dump_file(self._stderr, lines)
        lines.append('')
        lines.append(f'errorlog of {self._name}')
        lines.append('-------------------------------------------')
        self._dump_file(self._error_log, lines)
        lines.append('')
        return lines

    def _rmf(self, path):
        if os.path.isfile(path):
            return os.remove(path)

    def _dump_file(self, path, lines):
        if os.path.isfile(path):
            with open(path) as fd:
                for line in fd:
                    lines.append(line.rstrip())

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _log(self, level, msg):
        getattr(log, level)(f"[{self._name}] {msg}")

    def is_running(self):
        if self._process:
            self._process.poll()
            return self._process.returncode is None
        return False

    def initial_start(self):
        self._rmf(self._pid_file)
        self._rmf(self._error_log)
        self._mkpath(self._run_dir)
        self.write_config()

    def start(self, wait_live=True):
        self._mkpath(self._tmp_dir)
        self._mkpath(self._run_dir)
        if self._process:
            self.stop()
        self._loaded_cred_name = self._cred_name
        self.write_config()
        args = [self._cmd, '-c', self._conf_file]
        ngerr = open(self._stderr, 'a')
        self._process = subprocess.Popen(args=args, stderr=ngerr)
        if self._process.returncode is not None:
            return False
        if wait_live:
            time.sleep(1)
        return not wait_live or self.wait_for_state(live=True, timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def stop(self, wait_dead=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
            self._process = None
            return not wait_dead or self.wait_for_state(live=False, timeout=timedelta(seconds=5))
        return True

    def restart(self):
        self.stop()
        return self.start()

    def reload(self, timeout: timedelta = timedelta(seconds=Env.SERVER_TIMEOUT)):
        if self._process:
            running = self._process
            self._process = None
            os.kill(running.pid, signal.SIGQUIT)
            end_wait = datetime.now() + timedelta(seconds=5)
            if not self.start(wait_live=False):
                self._process = running
                return False
            while datetime.now() < end_wait:
                try:
                    self._log('debug', f'waiting for h2o({running.pid}) to exit.')
                    running.wait(1)
                    self._log('debug', f'h2o({running.pid}) terminated -> {running.returncode}')
                    running = None
                    break
                except subprocess.TimeoutExpired:
                    self._log('warning', f'h2o({running.pid}), not shut down yet.')
                    os.kill(running.pid, signal.SIGQUIT)
            if datetime.now() >= end_wait:
                self._log('error', f'h2o({running.pid}), terminate forcefully.')
                os.kill(running.pid, signal.SIGKILL)
                running.terminate()
                running.wait(1)
            return self.wait_for_state(live=True, timeout=timeout)
        return False

    def wait_for_state(self, live: bool, timeout: timedelta, url: Optional[str] = None, log_prefix: str = "h2o"):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        if url is None:
            url = f'https://{self._domain}:{self._port}/'
        while datetime.now() < try_until:
            if live:
                r = curl.http_get(url=url, extra_args=['--trace', 'curl.trace', '--trace-time'])
                if r.exit_code == 0:
                    return True
            else:
                r = curl.http_get(url=url)
                if r.exit_code != 0:
                    return True
            time.sleep(.1)
        if live:
            self._log('error', f"Server still not responding after {timeout}")
        else:
            self._log('debug', f"Server still responding after {timeout}")
        return False

    def write_config(self):
        # To be overridden by subclasses
        with open(self._conf_file, 'w') as fd:
            fd.write('# h2o test config\n')


class H2oServer(H2o):
    """h2o HTTP/3 server for testing"""
    PORT_SPECS = {
        'h2o_https': socket.SOCK_STREAM,
    }

    def __init__(self, env: Env):
        super().__init__(env=env, name='h2o-server', domain=env.domain1, cred_name=env.domain1)

    def initial_start(self):
        super().initial_start()
        def startup(ports: Dict[str, int]) -> bool:
            self._port = ports['h2o_https']
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._port = 0
            return False
        return alloc_ports_and_do(H2oServer.PORT_SPECS, startup, self.env.gen_root, max_tries=3)

    def write_config(self):
        creds = self.env.get_credentials(self._cred_name)
        doc_root = os.path.join(self.env.gen_dir, 'docs')
        self._mkpath(doc_root)
        self._mkpath(self._run_dir)
        # Create a simple test file
        with open(os.path.join(doc_root, 'data.json'), 'w') as f:
            f.write('{"message": "Hello from h2o HTTP/3 server"}\n')
        with open(self._conf_file, 'w') as fd:
            fd.write(f"""# h2o HTTP/3 server configuration
server-name: "h2o-test-server"
num-threads: 1

listen: &ssl_listen
  port: {self._port}
  ssl:
    certificate-file: {creds.cert_file}
    key-file: {creds.pkey_file}
    neverbleed: OFF
    minimum-version: TLSv1.2
    ocsp-update-interval: 0

listen:
  <<: *ssl_listen
  type: quic

hosts:
  "{self._domain}":
    paths:
      "/":
        file.dir: {doc_root}

http2-reprioritize-blocking-assets: ON

access-log: {self._run_dir}/access.log
error-log: {self._error_log}
""")


class H2oProxy(H2o):
    """h2o MASQUE proxy for testing"""
    def __init__(self, env: Env):
        super().__init__(env=env, name='h2o-proxy', domain=env.proxy_domain, cred_name=env.proxy_domain)

    def initial_start(self):
        super().initial_start()
        def startup(ports: Dict[str, int]) -> bool:
            self._port = ports['h3proxys']
            self._h2_port = ports.get('h2proxys', ports['h2proxys'])
            self._h1_port = ports.get('proxys', ports['proxys'])
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._port = 0
            self._h2_port = 0
            self._h1_port = 0
            return False
        return alloc_ports_and_do({
            'h3proxys': socket.SOCK_DGRAM,
            'h2proxys': socket.SOCK_STREAM,
            'proxys': socket.SOCK_STREAM
        }, startup, self.env.gen_root, max_tries=3)

    def write_config(self):
        creds = self.env.get_credentials(self._cred_name)
        self._mkpath(self._run_dir)
        with open(self._conf_file, 'w') as fd:
            fd.write(f"""# h2o MASQUE proxy configuration
server-name: "h2o-test-proxy"
num-threads: 1

proxy.tunnel: ON

# HTTP/1.1 proxy listener
listen: &h1_listen
  port: {getattr(self, '_h1_port', self._port)}
  ssl:
    certificate-file: {creds.cert_file}
    key-file: {creds.pkey_file}
    neverbleed: OFF
    minimum-version: TLSv1.2
    ocsp-update-interval: 0

# HTTP/2 proxy listener
listen: &h2_listen
  port: {getattr(self, '_h2_port', self._port)}
  ssl:
    certificate-file: {creds.cert_file}
    key-file: {creds.pkey_file}
    neverbleed: OFF
    minimum-version: TLSv1.2
    ocsp-update-interval: 0

# HTTP/3 proxy listener (main port)
listen: &h3_listen
  port: {self._port}
  ssl:
    certificate-file: {creds.cert_file}
    key-file: {creds.pkey_file}
    neverbleed: OFF
    minimum-version: TLSv1.2
    ocsp-update-interval: 0

# QUIC listener for HTTP/3
listen:
  <<: *h3_listen
  type: quic

hosts:
  "{self._domain}":
    paths:
      "/":
        proxy.connect: [+*]
        proxy.connect-udp: [+*]
        proxy.ssl.verify-peer: OFF

http2-reprioritize-blocking-assets: ON

access-log: {self._run_dir}/access.log
error-log: {self._error_log}
""")

    def wait_for_state(self, live: bool, timeout: timedelta, url: Optional[str] = None, log_prefix: str = "h2o-proxy"):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        if url is None:
            url = f'https://{self.env.proxy_domain}:{self._port}/'
        while datetime.now() < try_until:
            if live:
                r = curl.http_get(url=url, extra_args=['--trace', 'curl.trace', '--trace-time'])
                if r.exit_code == 0:
                    return True
            else:
                r = curl.http_get(url=url)
                if r.exit_code != 0:
                    return True
            time.sleep(.1)
        if live:
            self._log('error', f"Proxy still not responding after {timeout}")
        else:
            self._log('debug', f"Proxy still responding after {timeout}")
        return False