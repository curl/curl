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
import subprocess
import time
from typing import Optional
from datetime import datetime, timedelta

from .env import Env
from .curl import CurlClient


log = logging.getLogger(__name__)


class Nghttpx:

    def __init__(self, env: Env, port: int, https_port: int, name: str):
        self.env = env
        self._name = name
        self._port = port
        self._https_port = https_port
        self._cmd = env.nghttpx
        self._run_dir = os.path.join(env.gen_dir, name)
        self._pid_file = os.path.join(self._run_dir, 'nghttpx.pid')
        self._conf_file = os.path.join(self._run_dir, 'nghttpx.conf')
        self._error_log = os.path.join(self._run_dir, 'nghttpx.log')
        self._stderr = os.path.join(self._run_dir, 'nghttpx.stderr')
        self._tmp_dir = os.path.join(self._run_dir, 'tmp')
        self._process: Optional[subprocess.Popen] = None
        self._rmf(self._pid_file)
        self._rmf(self._error_log)
        self._mkpath(self._run_dir)
        self._write_config()

    @property
    def https_port(self):
        return self._https_port

    def exists(self):
        return self._cmd and os.path.exists(self._cmd)

    def clear_logs(self):
        self._rmf(self._error_log)
        self._rmf(self._stderr)

    def is_running(self):
        if self._process:
            self._process.poll()
            return self._process.returncode is None
        return False

    def start_if_needed(self):
        if not self.is_running():
            return self.start()
        return True

    def start(self, wait_live=True):
        pass

    def stop_if_running(self):
        if self.is_running():
            return self.stop()
        return True

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

    def reload(self, timeout: timedelta):
        if self._process:
            running = self._process
            self._process = None
            os.kill(running.pid, signal.SIGQUIT)
            end_wait = datetime.now() + timeout
            if not self.start(wait_live=False):
                self._process = running
                return False
            while datetime.now() < end_wait:
                try:
                    log.debug(f'waiting for nghttpx({running.pid}) to exit.')
                    running.wait(2)
                    log.debug(f'nghttpx({running.pid}) terminated -> {running.returncode}')
                    break
                except subprocess.TimeoutExpired:
                    log.warning(f'nghttpx({running.pid}), not shut down yet.')
                    os.kill(running.pid, signal.SIGQUIT)
            if datetime.now() >= end_wait:
                log.error(f'nghttpx({running.pid}), terminate forcefully.')
                os.kill(running.pid, signal.SIGKILL)
                running.terminate()
                running.wait(1)
            return self.wait_live(timeout=timedelta(seconds=5))
        return False

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            if self._https_port > 0:
                check_url = f'https://{self.env.domain1}:{self._https_port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
            else:
                check_url = f'https://{self.env.domain1}:{self._port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--trace', 'curl.trace', '--trace-time',
                    '--http3-only', '--connect-timeout', '1'
                ])
            if r.exit_code != 0:
                return True
            log.debug(f'waiting for nghttpx to stop responding: {r}')
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            if self._https_port > 0:
                check_url = f'https://{self.env.domain1}:{self._https_port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
            else:
                check_url = f'https://{self.env.domain1}:{self._port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--http3-only', '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
            if r.exit_code == 0:
                return True
            log.debug(f'waiting for nghttpx to become responsive: {r}')
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
        with open(self._conf_file, 'w') as fd:
            fd.write('# nghttpx test config')
            fd.write("\n".join([
                '# do we need something here?'
            ]))


class NghttpxQuic(Nghttpx):

    def __init__(self, env: Env):
        super().__init__(env=env, name='nghttpx-quic', port=env.h3_port,
                         https_port=env.nghttpx_https_port)

    def start(self, wait_live=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        creds = self.env.get_credentials(self.env.domain1)
        assert creds  # convince pytype this isn't None
        args = [
            self._cmd,
            f'--frontend=*,{self.env.h3_port};quic',
            f'--frontend=*,{self.env.nghttpx_https_port};tls',
            f'--backend=127.0.0.1,{self.env.https_port};{self.env.domain1};sni={self.env.domain1};proto=h2;tls',
            f'--backend=127.0.0.1,{self.env.http_port}',
            '--log-level=INFO',
            f'--pid-file={self._pid_file}',
            f'--errorlog-file={self._error_log}',
            f'--conf={self._conf_file}',
            f'--cacert={self.env.ca.cert_file}',
            creds.pkey_file,
            creds.cert_file,
            '--frontend-http3-window-size=1M',
            '--frontend-http3-max-window-size=10M',
            '--frontend-http3-connection-window-size=10M',
            '--frontend-http3-max-connection-window-size=100M',
            # f'--frontend-quic-debug-log',
        ]
        ngerr = open(self._stderr, 'a')
        self._process = subprocess.Popen(args=args, stderr=ngerr)
        if self._process.returncode is not None:
            return False
        return not wait_live or self.wait_live(timeout=timedelta(seconds=5))


class NghttpxFwd(Nghttpx):

    def __init__(self, env: Env):
        super().__init__(env=env, name='nghttpx-fwd', port=env.h2proxys_port,
                         https_port=0)

    def start(self, wait_live=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        creds = self.env.get_credentials(self.env.proxy_domain)
        assert creds  # convince pytype this isn't None
        args = [
            self._cmd,
            '--http2-proxy',
            f'--frontend=*,{self.env.h2proxys_port}',
            f'--backend=127.0.0.1,{self.env.proxy_port}',
            '--log-level=INFO',
            f'--pid-file={self._pid_file}',
            f'--errorlog-file={self._error_log}',
            f'--conf={self._conf_file}',
            f'--cacert={self.env.ca.cert_file}',
            creds.pkey_file,
            creds.cert_file,
        ]
        ngerr = open(self._stderr, 'a')
        self._process = subprocess.Popen(args=args, stderr=ngerr)
        if self._process.returncode is not None:
            return False
        return not wait_live or self.wait_live(timeout=timedelta(seconds=5))

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'https://{self.env.proxy_domain}:{self.env.h2proxys_port}/'
            r = curl.http_get(url=check_url)
            if r.exit_code != 0:
                return True
            log.debug(f'waiting for nghttpx-fwd to stop responding: {r}')
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'https://{self.env.proxy_domain}:{self.env.h2proxys_port}/'
            r = curl.http_get(url=check_url, extra_args=[
                '--trace', 'curl.trace', '--trace-time'
            ])
            if r.exit_code == 0:
                return True
            log.debug(f'waiting for nghttpx-fwd to become responsive: {r}')
            time.sleep(.1)
        log.error(f"Server still not responding after {timeout}")
        return False
