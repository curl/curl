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
import inspect
import logging
import os
import shutil
import socket
import subprocess
from datetime import timedelta, datetime
from json import JSONEncoder
import time
from typing import List, Union, Optional, Dict
import copy

from .curl import CurlClient, ExecResult
from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Httpd:

    MODULES = [
        'log_config', 'logio', 'unixd', 'version', 'watchdog',
        'authn_core', 'authn_file',
        'authz_user', 'authz_core', 'authz_host',
        'auth_basic', 'auth_digest',
        'alias', 'env', 'filter', 'headers', 'mime', 'setenvif', 'negotiation',
        'socache_shmcb',
        'rewrite', 'http2', 'ssl', 'proxy', 'proxy_http', 'proxy_connect',
        'brotli',
        'mpm_event',
    ]
    COMMON_MODULES_DIRS = [
        '/usr/lib/apache2/modules',  # debian
        '/usr/libexec/apache2/',     # macos
    ]

    MOD_CURLTEST = None

    PORT_SPECS = {
        'http': socket.SOCK_STREAM,
        'https': socket.SOCK_STREAM,
        'https-tcp-only': socket.SOCK_STREAM,
        'proxy': socket.SOCK_STREAM,
        'proxys': socket.SOCK_STREAM,
    }

    def __init__(self, env: Env):
        self.env = env
        self._apache_dir = os.path.join(env.gen_dir, 'apache')
        self._run_dir = os.path.join(self._apache_dir, 'run')
        self._lock_dir = os.path.join(self._apache_dir, 'locks')
        self._docs_dir = os.path.join(self._apache_dir, 'docs')
        self._conf_dir = os.path.join(self._apache_dir, 'conf')
        self._conf_file = os.path.join(self._conf_dir, 'test.conf')
        self._logs_dir = os.path.join(self._apache_dir, 'logs')
        self._error_log = os.path.join(self._logs_dir, 'error_log')
        self._tmp_dir = os.path.join(self._apache_dir, 'tmp')
        self._basic_passwords = os.path.join(self._conf_dir, 'basic.passwords')
        self._digest_passwords = os.path.join(self._conf_dir, 'digest.passwords')
        self._mods_dir = None
        self._auth_digest = True
        self._proxy_auth_basic = False
        # name used to lookup credentials for env.domain1
        self._domain1_cred_name = env.domain1
        self._extra_configs = {}
        self._loaded_extra_configs = None
        self._loaded_proxy_auth = None
        self._loaded_domain1_cred_name = None
        assert env.apxs
        p = subprocess.run(args=[env.apxs, '-q', 'libexecdir'],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise Exception(f'{env.apxs} failed to query libexecdir: {p}')
        self._mods_dir = p.stdout.strip()
        if self._mods_dir is None:
            raise Exception('apache modules dir cannot be found')
        if not os.path.exists(self._mods_dir):
            raise Exception(f'apache modules dir does not exist: {self._mods_dir}')
        self._maybe_running = False
        self.ports = {}
        self._rmf(self._error_log)
        self._init_curltest()

    @property
    def docs_dir(self):
        return self._docs_dir

    def clear_logs(self):
        self._rmf(self._error_log)

    def exists(self):
        return os.path.exists(self.env.httpd)

    def set_extra_config(self, domain: str, lines: Optional[Union[str, List[str]]]):
        if lines is None:
            self._extra_configs.pop(domain, None)
        else:
            self._extra_configs[domain] = lines

    def reset_config(self):
        self._extra_configs = {}
        self.set_proxy_auth(False)
        self._domain1_cred_name = self.env.domain1

    def set_proxy_auth(self, active: bool):
        self._proxy_auth_basic = active

    def set_domain1_cred_name(self, name):
        self._domain1_cred_name = name

    def _run(self, args, intext=''):
        env = os.environ.copy()
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

    def _cmd_httpd(self, cmd: str):
        args = [self.env.httpd,
                "-d", self._apache_dir,
                "-f", self._conf_file,
                "-k", cmd]
        return self._run(args=args)

    def initial_start(self):

        def startup(ports: Dict[str, int]) -> bool:
            self.ports.update(ports)
            if self.start():
                self.env.update_ports(ports)
                return True
            self.stop()
            self.ports.clear()
            return False

        return alloc_ports_and_do(Httpd.PORT_SPECS, startup,
                                  self.env.gen_root, max_tries=3)

    def start(self):
        # assure ports are allocated
        for key, _ in Httpd.PORT_SPECS.items():
            assert self.ports[key] is not None
        if self._maybe_running:
            self.stop()
        self._write_config()
        with open(self._error_log, 'a') as fd:
            fd.write('start of server\n')
        with open(os.path.join(self._apache_dir, 'xxx'), 'a') as fd:
            fd.write('start of server\n')
        r = self._cmd_httpd('start')
        if r.exit_code != 0 or len(r.stderr):
            log.error(f'failed to start httpd: {r}')
            self.stop()
            return False
        self._loaded_extra_configs = copy.deepcopy(self._extra_configs)
        self._loaded_proxy_auth = self._proxy_auth_basic
        return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def stop(self):
        r = self._cmd_httpd('stop')
        self._loaded_extra_configs = None
        self._loaded_proxy_auth = None
        if r.exit_code == 0:
            return self.wait_dead(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))
        log.fatal(f'stopping httpd failed: {r}')
        return r.exit_code == 0

    def reload(self):
        self._write_config()
        r = self._cmd_httpd("graceful")
        if r.exit_code != 0:
            log.error(f'failed to reload httpd: {r}')
            return False
        self._loaded_extra_configs = None
        self._loaded_proxy_auth = None
        if r.exit_code != 0:
            log.error(f'failed to reload httpd: {r}')
        self._loaded_extra_configs = copy.deepcopy(self._extra_configs)
        self._loaded_proxy_auth = self._proxy_auth_basic
        return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def reload_if_config_changed(self):
        if self._maybe_running and \
                self._loaded_extra_configs == self._extra_configs and \
                self._loaded_proxy_auth == self._proxy_auth_basic and \
                self._loaded_domain1_cred_name == self._domain1_cred_name:
            return True
        return self.reload()

    def wait_dead(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir)
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'http://{self.env.domain1}:{self.ports["http"]}/')
            if r.exit_code != 0:
                self._maybe_running = False
                return True
            time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
        return False

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir,
                          timeout=timeout.total_seconds())
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'http://{self.env.domain1}:{self.ports["http"]}/')
            if r.exit_code == 0:
                self._maybe_running = True
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
        domain1 = self.env.domain1
        domain1brotli = self.env.domain1brotli
        creds1 = self.env.get_credentials(self._domain1_cred_name)
        assert creds1  # convince pytype this isn't None
        self._loaded_domain1_cred_name = self._domain1_cred_name
        domain2 = self.env.domain2
        creds2 = self.env.get_credentials(domain2)
        assert creds2  # convince pytype this isn't None
        exp_domain = self.env.expired_domain
        exp_creds = self.env.get_credentials(exp_domain)
        assert exp_creds  # convince pytype this isn't None
        proxy_domain = self.env.proxy_domain
        proxy_creds = self.env.get_credentials(proxy_domain)
        assert proxy_creds  # convince pytype this isn't None
        self._mkpath(self._conf_dir)
        self._mkpath(self._docs_dir)
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
        if self._proxy_auth_basic:
            with open(self._basic_passwords, 'w') as fd:
                fd.write('proxy:$apr1$FQfeInbs$WQZbODJlVg60j0ogEIlTW/\n')
        if self._auth_digest:
            with open(self._digest_passwords, 'w') as fd:
                fd.write('test:restricted area:57123e269fd73d71ae0656594e938e2f\n')
            self._mkpath(os.path.join(self.docs_dir, 'restricted/digest'))
            with open(os.path.join(self.docs_dir, 'restricted/digest/data.json'), 'w') as fd:
                fd.write('{"area":"digest"}\n')
        with open(self._conf_file, 'w') as fd:
            for m in self.MODULES:
                if os.path.exists(os.path.join(self._mods_dir, f'mod_{m}.so')):
                    fd.write(f'LoadModule {m}_module   "{self._mods_dir}/mod_{m}.so"\n')
            if Httpd.MOD_CURLTEST is not None:
                fd.write(f'LoadModule curltest_module   "{Httpd.MOD_CURLTEST}"\n')
            conf = [   # base server config
                f'ServerRoot "{self._apache_dir}"',
                'DefaultRuntimeDir logs',
                'PidFile httpd.pid',
                f'ServerName {self.env.tld}',
                f'ErrorLog {self._error_log}',
                f'LogLevel {self._get_log_level()}',
                'StartServers 4',
                'ReadBufferSize 16000',
                'KeepAliveTimeout 30',  # CI may exceed the default of 5 sec
                'H2MinWorkers 16',
                'H2MaxWorkers 256',
                f'TypesConfig "{self._conf_dir}/mime.types',
                'SSLSessionCache "shmcb:ssl_gcache_data(32000)"',
                'AddEncoding x-gzip .gz .tgz .gzip',
                'AddHandler type-map .var',
            ]
            conf.extend([f'Listen {port}' for _, port in self.ports.items()])

            if 'base' in self._extra_configs:
                conf.extend(self._extra_configs['base'])
            conf.extend([  # plain http host for domain1
                f'<VirtualHost *:{self.ports["http"]}>',
                f'    ServerName {domain1}',
                '    ServerAlias localhost',
                f'    DocumentRoot "{self._docs_dir}"',
                '    Protocols h2c http/1.1',
                '    H2Direct on',
            ])
            conf.extend(self._curltest_conf(domain1))
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # https host for domain1, h1 + h2
                f'<VirtualHost *:{self.ports["https"]}>',
                f'    ServerName {domain1}',
                '    ServerAlias localhost',
                '    Protocols h2 http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {creds1.cert_file}',
                f'    SSLCertificateKeyFile {creds1.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}"',
            ])
            conf.extend(self._curltest_conf(domain1))
            if domain1 in self._extra_configs:
                conf.extend(self._extra_configs[domain1])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # https host for domain1, h1 + h2, tcp only
                f'<VirtualHost *:{self.ports["https-tcp-only"]}>',
                f'    ServerName {domain1}',
                '    ServerAlias localhost',
                '    Protocols h2 http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {creds1.cert_file}',
                f'    SSLCertificateKeyFile {creds1.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}"',
            ])
            conf.extend(self._curltest_conf(domain1))
            if domain1 in self._extra_configs:
                conf.extend(self._extra_configs[domain1])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            # Alternate to domain1 with BROTLI compression
            conf.extend([  # https host for domain1, h1 + h2
                f'<VirtualHost *:{self.ports["https"]}>',
                f'    ServerName {domain1brotli}',
                '    Protocols h2 http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {creds1.cert_file}',
                f'    SSLCertificateKeyFile {creds1.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}"',
                '    SetOutputFilter BROTLI_COMPRESS',
            ])
            conf.extend(self._curltest_conf(domain1))
            if domain1 in self._extra_configs:
                conf.extend(self._extra_configs[domain1])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # plain http host for domain2
                f'<VirtualHost *:{self.ports["http"]}>',
                f'    ServerName {domain2}',
                '    ServerAlias localhost',
                f'    DocumentRoot "{self._docs_dir}"',
                '    Protocols h2c http/1.1',
            ])
            conf.extend(self._curltest_conf(domain2))
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            self._mkpath(os.path.join(self._docs_dir, 'two'))
            conf.extend([  # https host for domain2, no h2
                f'<VirtualHost *:{self.ports["https"]}>',
                f'    ServerName {domain2}',
                '    Protocols http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {creds2.cert_file}',
                f'    SSLCertificateKeyFile {creds2.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}/two"',
            ])
            conf.extend(self._curltest_conf(domain2))
            if domain2 in self._extra_configs:
                conf.extend(self._extra_configs[domain2])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # https host for domain2, no h2, tcp only
                f'<VirtualHost *:{self.ports["https-tcp-only"]}>',
                f'    ServerName {domain2}',
                '    Protocols http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {creds2.cert_file}',
                f'    SSLCertificateKeyFile {creds2.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}/two"',
            ])
            conf.extend(self._curltest_conf(domain2))
            if domain2 in self._extra_configs:
                conf.extend(self._extra_configs[domain2])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            self._mkpath(os.path.join(self._docs_dir, 'expired'))
            conf.extend([  # https host for expired domain
                f'<VirtualHost *:{self.ports["https"]}>',
                f'    ServerName {exp_domain}',
                '    Protocols h2 http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {exp_creds.cert_file}',
                f'    SSLCertificateKeyFile {exp_creds.pkey_file}',
                f'    DocumentRoot "{self._docs_dir}/expired"',
            ])
            conf.extend(self._curltest_conf(exp_domain))
            if exp_domain in self._extra_configs:
                conf.extend(self._extra_configs[exp_domain])
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # http forward proxy
                f'<VirtualHost *:{self.ports["proxy"]}>',
                f'    ServerName {proxy_domain}',
                '    Protocols h2c http/1.1',
                '    ProxyRequests On',
                '    H2ProxyRequests On',
                '    ProxyVia On',
                f'    AllowCONNECT {self.ports["http"]} {self.ports["https"]}',
            ])
            conf.extend(self._get_proxy_conf())
            conf.extend([
                '</VirtualHost>',
                '',
            ])
            conf.extend([  # https forward proxy
                f'<VirtualHost *:{self.ports["proxys"]}>',
                f'    ServerName {proxy_domain}',
                '    Protocols h2 http/1.1',
                '    SSLEngine on',
                f'    SSLCertificateFile {proxy_creds.cert_file}',
                f'    SSLCertificateKeyFile {proxy_creds.pkey_file}',
                '    ProxyRequests On',
                '    H2ProxyRequests On',
                '    ProxyVia On',
                f'    AllowCONNECT {self.ports["http"]} {self.ports["https"]}',
            ])
            conf.extend(self._get_proxy_conf())
            conf.extend([
                '</VirtualHost>',
                '',
            ])

            fd.write("\n".join(conf))
        with open(os.path.join(self._conf_dir, 'mime.types'), 'w') as fd:
            fd.write("\n".join([
                'text/plain            txt',
                'text/html             html',
                'application/json      json',
                'application/x-gzip    gzip',
                'application/x-gzip    gz',
                ''
            ]))

    def _get_proxy_conf(self):
        if self._proxy_auth_basic:
            return [
                '    <Proxy "*">',
                '      AuthType Basic',
                '      AuthName "Restricted Proxy"',
                '      AuthBasicProvider file',
                f'      AuthUserFile "{self._basic_passwords}"',
                '      Require user proxy',
                '    </Proxy>',
            ]
        else:
            return [
                '    <Proxy "*">',
                '      Require ip 127.0.0.1',
                '    </Proxy>',
            ]

    def _get_log_level(self):
        if self.env.verbose > 3:
            return 'trace2'
        if self.env.verbose > 2:
            return 'trace1'
        if self.env.verbose > 1:
            return 'debug'
        return 'info'

    def _curltest_conf(self, servername) -> List[str]:
        lines = []
        if Httpd.MOD_CURLTEST is not None:
            lines.extend([
                '    Redirect 302 /data.json.302 /data.json',
                '    Redirect 301 /curltest/echo301 /curltest/echo',
                '    Redirect 302 /curltest/echo302 /curltest/echo',
                '    Redirect 303 /curltest/echo303 /curltest/echo',
                '    Redirect 307 /curltest/echo307 /curltest/echo',
                '    <Location /curltest/sslinfo>',
                '      SSLOptions StdEnvVars',
                '      SetHandler curltest-sslinfo',
                '    </Location>',
                '    <Location /curltest/echo>',
                '      SetHandler curltest-echo',
                '    </Location>',
                '    <Location /curltest/put>',
                '      SetHandler curltest-put',
                '    </Location>',
                '    <Location /curltest/tweak>',
                '      SetHandler curltest-tweak',
                '    </Location>',
                '    Redirect 302 /tweak /curltest/tweak',
                '    <Location /curltest/1_1>',
                '      SetHandler curltest-1_1-required',
                '    </Location>',
                '    <Location /curltest/shutdown_unclean>',
                '      SetHandler curltest-tweak',
                '      SetEnv force-response-1.0 1',
                '    </Location>',
                '    SetEnvIf Request_URI "/shutdown_unclean" ssl-unclean=1',
                '    RewriteEngine on',
                '    RewriteRule    "^/curltest/put-redir-301$"  "/curltest/put"  [R=301]',
                '    RewriteRule    "^/curltest/put-redir-302$"  "/curltest/put"  [R=302]',
                '    RewriteRule    "^/curltest/put-redir-307$"  "/curltest/put"  [R=307]',
                '    RewriteRule    "^/curltest/put-redir-308$"  "/curltest/put"  [R=308]',
            ])
        if self._auth_digest:
            lines.extend([
                f'    <Directory {self.docs_dir}/restricted/digest>',
                '      AuthType Digest',
                '      AuthName "restricted area"',
                f'      AuthDigestDomain "https://{servername}"',
                '      AuthBasicProvider file',
                f'      AuthUserFile "{self._digest_passwords}"',
                '      Require valid-user',
                '    </Directory>',

            ])
        return lines

    def _init_curltest(self):
        if Httpd.MOD_CURLTEST is not None:
            return
        local_dir = os.path.dirname(inspect.getfile(Httpd))
        out_dir = os.path.join(self.env.gen_dir, 'mod_curltest')
        out_source = os.path.join(out_dir, 'mod_curltest.c')
        if not os.path.exists(out_dir):
            os.mkdir(out_dir)
        if not os.path.exists(out_source):
            shutil.copy(os.path.join(local_dir, 'mod_curltest/mod_curltest.c'), out_source)
        p = subprocess.run([
            self.env.apxs, '-c', out_source
        ], capture_output=True, cwd=out_dir)
        rv = p.returncode
        if rv != 0:
            log.error(f"compiling mod_curltest failed: {p.stderr}")
            raise Exception(f"compiling mod_curltest failed: {p.stderr}")
        Httpd.MOD_CURLTEST = os.path.join(out_dir, '.libs/mod_curltest.so')
