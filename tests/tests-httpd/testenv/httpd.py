#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2008 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
import inspect
import logging
import os
import subprocess
from datetime import timedelta, datetime
from json import JSONEncoder
import time
from typing import List

from .curl import CurlClient, ExecResult
from .env import Env


log = logging.getLogger(__name__)


class Httpd:

    MODULES = [
        'log_config', 'logio', 'unixd', 'version', 'watchdog',
        'authn_core', 'authz_user', 'authz_core',
        'env', 'filter', 'headers', 'mime',
        'rewrite', 'http2', 'ssl',
        'mpm_event',
    ]
    COMMON_MODULES_DIRS = [
        '/usr/lib/apache2/modules',  # debian
        '/usr/libexec/apache2/',     # macos
    ]

    MOD_CURLTEST = None

    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.apachectl
        self._apache_dir = os.path.join(env.gen_dir, 'apache')
        self._run_dir = os.path.join(self._apache_dir, 'run')
        self._lock_dir = os.path.join(self._apache_dir, 'locks')
        self._docs_dir = os.path.join(self._apache_dir, 'docs')
        self._conf_dir = os.path.join(self._apache_dir, 'conf')
        self._conf_file = os.path.join(self._conf_dir, 'test.conf')
        self._logs_dir = os.path.join(self._apache_dir, 'logs')
        self._error_log = os.path.join(self._logs_dir, 'error_log')
        self._tmp_dir = os.path.join(self._apache_dir, 'tmp')
        self._mods_dir = None
        assert env.apxs
        p = subprocess.run(args=[env.apxs, '-q', 'libexecdir'],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise Exception(f'{env.apxs} failed to query libexecdir: {p}')
        self._mods_dir = p.stdout.strip()
        if self._mods_dir is None:
            raise Exception(f'apache modules dir cannot be found')
        if not os.path.exists(self._mods_dir):
            raise Exception(f'apache modules dir does not exist: {self._mods_dir}')
        self._process = None
        self._rmf(self._error_log)
        self._init_curltest()

    @property
    def docs_dir(self):
        return self._docs_dir

    def clear_logs(self):
        self._rmf(self._error_log)

    def exists(self):
        return os.path.exists(self._cmd)

    def _run(self, args, intext=''):
        env = {}
        for key, val in os.environ.items():
            env[key] = val
        env['APACHE_RUN_DIR'] = self._run_dir
        env['APACHE_RUN_USER'] = os.environ['USER']
        env['APACHE_LOCK_DIR'] = self._lock_dir
        env['APACHE_CONFDIR'] = self._apache_dir
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           cwd=self.env.gen_dir,
                           input=intext.encode() if intext else None,
                           env=env)
        start = datetime.now()
        return ExecResult(args=args, exit_code=p.returncode,
                          stdout=p.stdout.decode().splitlines(),
                          stderr=p.stderr.decode().splitlines(),
                          duration=datetime.now() - start)

    def _apachectl(self, cmd: str):
        args = [self.env.apachectl,
                "-d", self._apache_dir,
                "-f", self._conf_file,
                "-k", cmd]
        return self._run(args=args)

    def start(self):
        if self._process:
            self.stop()
        self._write_config()
        with open(self._error_log, 'a') as fd:
            fd.write('start of server\n')
        with open(os.path.join(self._apache_dir, 'xxx'), 'a') as fd:
            fd.write('start of server\n')
        r = self._apachectl('start')
        if r.exit_code != 0:
            log.error(f'failed to start httpd: {r}')
            return False
        return self.wait_live(timeout=timedelta(seconds=5))

    def stop(self):
        r = self._apachectl('stop')
        if r.exit_code == 0:
            return self.wait_dead(timeout=timedelta(seconds=5))
        return r.exit_code == 0

    def restart(self):
        self.stop()
        return self.start()

    def reload(self):
        r = self._apachectl("graceful")
        if r.exit_code != 0:
            log.error(f'failed to reload httpd: {r}')
        return self.wait_live(timeout=timedelta(seconds=5))

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'http://{self.env.domain1}:{self.env.http_port}/')
            if r.exit_code != 0:
                return True
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'http://{self.env.domain1}:{self.env.http_port}/')
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        log.debug(f"Server still not responding after {timeout}")
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
        domain2 = self.env.domain2
        creds2 = self.env.get_credentials(domain2)
        self._mkpath(self._conf_dir)
        self._mkpath(self._logs_dir)
        self._mkpath(self._tmp_dir)
        self._mkpath(os.path.join(self._docs_dir, 'two'))
        with open(os.path.join(self._docs_dir, 'data.json'), 'w') as fd:
            data = {
                'server': f'{domain1}',
            }
            fd.write(JSONEncoder().encode(data))
        with open(os.path.join(self._docs_dir, 'two/data.json'), 'w') as fd:
            data = {
                'server': f'{domain2}',
            }
            fd.write(JSONEncoder().encode(data))
        with open(self._conf_file, 'w') as fd:
            for m in self.MODULES:
                if os.path.exists(os.path.join(self._mods_dir, f'mod_{m}.so')):
                    fd.write(f'LoadModule {m}_module   "{self._mods_dir}/mod_{m}.so"\n')
            if Httpd.MOD_CURLTEST is not None:
                fd.write(f'LoadModule curltest_module   \"{Httpd.MOD_CURLTEST}\"\n')
            conf = [   # base server config
                f'ServerRoot "{self._apache_dir}"',
                f'DefaultRuntimeDir logs',
                f'PidFile httpd.pid',
                f'ErrorLog {self._error_log}',
                f'LogLevel {self._get_log_level()}',
                f'LogLevel http:trace4',
                f'H2MinWorkers 16',
                f'H2MaxWorkers 128',
                f'Listen {self.env.http_port}',
                f'Listen {self.env.https_port}',
                f'TypesConfig "{self._conf_dir}/mime.types',
            ]
            conf.extend([  # plain http host for domain1
                f'<VirtualHost *:{self.env.http_port}>',
                f'    ServerName {domain1}',
                f'    DocumentRoot "{self._docs_dir}"',
            ])
            conf.extend(self._curltest_conf())
            conf.extend([
                f'</VirtualHost>',
                f'',
            ])
            conf.extend([  # https host for domain1, h1 + h2
                f'<VirtualHost *:{self.env.https_port}>',
                f'    ServerName {domain1}',
                f'    Protocols h2 http/1.1',
                f'    SSLEngine on',
                f'    SSLCertificateFile {creds1.cert_file}',
                f'    SSLCertificateKeyFile {creds1.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}"',
            ])
            conf.extend(self._curltest_conf())
            conf.extend([
                f'</VirtualHost>',
                f'',
            ])
            conf.extend([  # https host for domain2, no h2
                f'<VirtualHost *:{self.env.https_port}>',
                f'    ServerName {domain2}',
                f'    Protocols http/1.1',
                f'    SSLEngine on',
                f'    SSLCertificateFile {creds2.cert_file}',
                f'    SSLCertificateKeyFile {creds2.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}/two"',
            ])
            conf.extend(self._curltest_conf())
            conf.extend([
                f'</VirtualHost>',
                f'',
            ])
            fd.write("\n".join(conf))
        with open(os.path.join(self._conf_dir, 'mime.types'), 'w') as fd:
            fd.write("\n".join([
                'text/html             html',
                'application/json      json',
                ''
            ]))

    def _get_log_level(self):
        if self.env.verbose > 3:
            return 'trace2'
        if self.env.verbose > 2:
            return 'trace1'
        if self.env.verbose > 1:
            return 'debug'
        return 'info'

    def _curltest_conf(self) -> List[str]:
        if Httpd.MOD_CURLTEST is not None:
            return [
                f'    <Location /curltest/echo>',
                f'      SetHandler curltest-echo',
                f'    </Location>',
                f'    <Location /curltest/tweak>',
                f'      SetHandler curltest-tweak',
                f'    </Location>',
            ]
        return []

    def _init_curltest(self):
        if Httpd.MOD_CURLTEST is not None:
            return
        local_dir = os.path.dirname(inspect.getfile(Httpd))
        p = subprocess.run([self.env.apxs, '-c', 'mod_curltest.c'],
                           capture_output=True,
                           cwd=os.path.join(local_dir, 'mod_curltest'))
        rv = p.returncode
        if rv != 0:
            log.error(f"compiling mod_curltest failed: {p.stderr}")
            raise Exception(f"compiling mod_curltest failed: {p.stderr}")
        Httpd.MOD_CURLTEST = os.path.join(
            local_dir, 'mod_curltest/.libs/mod_curltest.so')
