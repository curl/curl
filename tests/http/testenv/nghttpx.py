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

from .env import Env, NghttpxUtil
from .curl import CurlClient
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Nghttpx:

    def __init__(self, env: Env, name: str, domain: str, cred_name: str):
        self.env = env
        self._name = name
        self._domain = domain
        self._port = 0
        self._https_port = 0
        self._cmd = env.nghttpx
        self._run_dir = os.path.join(env.gen_dir, name)
        self._pid_file = os.path.join(self._run_dir, 'nghttpx.pid')
        self._conf_file = os.path.join(self._run_dir, 'nghttpx.conf')
        self._error_log = os.path.join(self._run_dir, 'nghttpx.log')
        self._stderr = os.path.join(self._run_dir, 'nghttpx.stderr')
        self._tmp_dir = os.path.join(self._run_dir, 'tmp')
        self._process: Optional[subprocess.Popen] = None
        self._cred_name = self._def_cred_name = cred_name
        self._loaded_cred_name = ''
        self._version = NghttpxUtil.version(self._cmd)

    def supports_h3(self):
        return NghttpxUtil.version_with_h3(self._version)

    def set_cred_name(self, name: str):
        self._cred_name = name

    def reset_config(self):
        self._cred_name = self._def_cred_name

    def reload_if_config_changed(self):
        if self._process and self._port > 0 and \
                self._loaded_cred_name == self._cred_name:
            return True
        return self.reload()

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

    def initial_start(self):
        self._rmf(self._pid_file)
        self._rmf(self._error_log)
        self._mkpath(self._run_dir)
        self._write_config()

    def start(self, wait_live=True):
        pass

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

    def reload(self, timeout: timedelta = timedelta(seconds=Env.SERVER_TIMEOUT)):
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
            return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))
        return False

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            if self._https_port > 0:
                check_url = f'https://{self._domain}:{self._port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
            else:
                check_url = f'https://{self._domain}:{self._port}/'
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
                check_url = f'https://{self._domain}:{self._port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
            else:
                check_url = f'https://{self._domain}:{self._port}/'
                r = curl.http_get(url=check_url, extra_args=[
                    '--http3-only', '--trace', 'curl.trace', '--trace-time',
                    '--connect-timeout', '1'
                ])
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
        with open(self._conf_file, 'w') as fd:
            fd.write('# nghttpx test config')
            fd.write("\n".join([
                '# do we need something here?'
            ]))


class NghttpxQuic(Nghttpx):

    PORT_SPECS = {
        'nghttpx_https': socket.SOCK_STREAM,
    }

    def __init__(self, env: Env):
        super().__init__(env=env, name='nghttpx-quic',
                         domain=env.domain1, cred_name=env.domain1)
        self._https_port = env.https_port

    def initial_start(self):
        super().initial_start()

        def startup(ports: Dict[str, int]) -> bool:
            self._port = ports['nghttpx_https']
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._port = 0
            return False

        return alloc_ports_and_do(NghttpxQuic.PORT_SPECS, startup,
                                  self.env.gen_root, max_tries=3)

    def start(self, wait_live=True):
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        creds = self.env.get_credentials(self._cred_name)
        assert creds  # convince pytype this isn't None
        self._loaded_cred_name = self._cred_name
        args = [self._cmd, f'--frontend=*,{self._port};tls']
        if self.supports_h3():
            args.extend([
                f'--frontend=*,{self.env.h3_port};quic',
                '--frontend-quic-early-data',
            ])
        args.extend([
            f'--backend=127.0.0.1,{self.env.https_port};{self._domain};sni={self._domain};proto=h2;tls',
            f'--backend=127.0.0.1,{self.env.http_port}',
            '--log-level=ERROR',
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
        ])
        ngerr = open(self._stderr, 'a')
        self._process = subprocess.Popen(args=args, stderr=ngerr)
        if self._process.returncode is not None:
            return False
        return not wait_live or self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))


class NghttpxFwd(Nghttpx):

    def __init__(self, env: Env):
        super().__init__(env=env, name='nghttpx-fwd',
                         domain=env.proxy_domain,
                         cred_name=env.proxy_domain)

    def initial_start(self):
        super().initial_start()

        def startup(ports: Dict[str, int]) -> bool:
            self._port = ports['h2proxys']
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self._port = 0
            return False

        return alloc_ports_and_do({'h2proxys': socket.SOCK_STREAM},
                                  startup, self.env.gen_root, max_tries=3)

    def start(self, wait_live=True):
        assert self._port > 0
        self._mkpath(self._tmp_dir)
        if self._process:
            self.stop()
        creds = self.env.get_credentials(self._cred_name)
        assert creds  # convince pytype this isn't None
        self._loaded_cred_name = self._cred_name
        args = [
            self._cmd,
            '--http2-proxy',
            f'--frontend=*,{self._port}',
            f'--backend=127.0.0.1,{self.env.proxy_port}',
            '--log-level=ERROR',
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
        return not wait_live or self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'https://{self.env.proxy_domain}:{self._port}/'
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
            check_url = f'https://{self.env.proxy_domain}:{self._port}/'
            r = curl.http_get(url=check_url, extra_args=[
                '--trace', 'curl.trace', '--trace-time'
            ])
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        log.error(f"Server still not responding after {timeout}")
        return False
