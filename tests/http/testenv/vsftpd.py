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
import re
import socket
import subprocess
import time

from datetime import datetime, timedelta
from typing import List, Dict

from .curl import CurlClient, ExecResult
from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class VsFTPD:

    def __init__(self, env: Env, with_ssl=False, ssl_implicit=False):
        self.env = env
        self._cmd = env.vsftpd
        self._port = 0
        self._with_ssl = with_ssl
        self._ssl_implicit = ssl_implicit and with_ssl
        self._scheme = 'ftps' if self._ssl_implicit else 'ftp'
        if self._with_ssl:
            self.name = 'vsftpds'
            self._port_skey = 'ftps'
            self._port_specs = {
                'ftps': socket.SOCK_STREAM,
            }
        else:
            self.name = 'vsftpd'
            self._port_skey = 'ftp'
            self._port_specs = {
                'ftp': socket.SOCK_STREAM,
            }
        self._vsftpd_dir = os.path.join(env.gen_dir, self.name)
        self._run_dir = os.path.join(self._vsftpd_dir, 'run')
        self._docs_dir = os.path.join(self._vsftpd_dir, 'docs')
        self._tmp_dir = os.path.join(self._vsftpd_dir, 'tmp')
        self._conf_file = os.path.join(self._vsftpd_dir, 'test.conf')
        self._pid_file = os.path.join(self._vsftpd_dir, 'vsftpd.pid')
        self._error_log = os.path.join(self._vsftpd_dir, 'vsftpd.log')
        self._process = None

        self.clear_logs()

    @property
    def domain(self):
        return self.env.ftp_domain

    @property
    def docs_dir(self):
        return self._docs_dir

    @property
    def port(self) -> int:
        return self._port

    def clear_logs(self):
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
            f'{self._conf_file}',
        ]
        procerr = open(self._error_log, 'a')
        self._process = subprocess.Popen(args=args, stderr=procerr)
        if self._process.returncode is not None:
            return False
        return not wait_live or self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'{self._scheme}://{self.domain}:{self.port}/'
            r = curl.ftp_get(urls=[check_url], extra_args=['-v'])
            if r.exit_code != 0:
                return True
            log.debug(f'waiting for vsftpd to stop responding: {r}')
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            check_url = f'{self._scheme}://{self.domain}:{self.port}/'
            r = curl.ftp_get(urls=[check_url], extra_args=[
                '--trace', 'curl-start.trace', '--trace-time'
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
        self._mkpath(self._docs_dir)
        self._mkpath(self._tmp_dir)
        conf = [  # base server config
            'listen=YES',
            'run_as_launching_user=YES',
            '#listen_address=127.0.0.1',
            f'listen_port={self.port}',
            'local_enable=NO',
            'anonymous_enable=YES',
            f'anon_root={self._docs_dir}',
            'dirmessage_enable=YES',
            'write_enable=YES',
            'anon_upload_enable=YES',
            'log_ftp_protocol=YES',
            'xferlog_enable=YES',
            'xferlog_std_format=NO',
            f'vsftpd_log_file={self._error_log}',
            '\n',
        ]
        if self._with_ssl:
            creds = self.env.get_credentials(self.domain)
            assert creds  # convince pytype this isn't None
            conf.extend([
                'ssl_enable=YES',
                'debug_ssl=YES',
                'allow_anon_ssl=YES',
                f'rsa_cert_file={creds.cert_file}',
                f'rsa_private_key_file={creds.pkey_file}',
                # require_ssl_reuse=YES means ctrl and data connection need to use the same session
                'require_ssl_reuse=NO',
            ])
            if self._ssl_implicit:
                conf.extend([
                     'implicit_ssl=YES',
                ])
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join(conf))

    def get_data_ports(self, r: ExecResult) -> List[int]:
        return [int(m.group(1)) for line in r.trace_lines if
                (m := re.match(r'.*Established 2nd connection to .* \(\S+ port (\d+)\)', line))]
