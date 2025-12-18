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
import stat
import subprocess
import time
from datetime import timedelta, datetime

from typing import Dict

from . import CurlClient
from .env import Env
from .ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class Sshd:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = Env.CONFIG.sshd
        self._sftpd = Env.CONFIG.sftpd
        self._keygen = 'ssh-keygen'
        self._port = 0
        self.name = 'sshd'
        self._port_skey = 'sshd'
        self._port_specs = {
            'sshd': socket.SOCK_STREAM,
        }
        self._sshd_dir = os.path.join(env.gen_dir, self.name)
        self._home_dir = os.path.join(self._sshd_dir, 'home')
        self._run_dir = os.path.join(self._sshd_dir, 'run')
        self._tmp_dir = os.path.join(self._sshd_dir, 'tmp')
        self._conf_file = os.path.join(self._sshd_dir, 'test.conf')
        self._auth_keys = os.path.join(self._sshd_dir, 'authorized_keys')
        self._known_hosts = os.path.join(self._sshd_dir, 'known_hosts')
        self._unknown_hosts = os.path.join(self._sshd_dir, 'unknown_hosts')
        self._sshd_log = os.path.join(self._sshd_dir, 'sshd.log')
        self._pid_file = os.path.join(self._sshd_dir, 'sshd.pid')
        self._key_algs = [
            'rsa', 'ecdsa', 'ed25519',
        ]
        self._host_key_files = []
        self._host_pub_files = []
        self._users = [
            'user1',
            'user2',
        ]
        self._user_key_files = []
        self._user_pub_files = []
        self._process = None

        self.clear_logs()
        self._mkpath(self._home_dir)
        env.make_data_file(indir=self._home_dir, fname="data", fsize=1024)
        self._mkpath(self._tmp_dir)

    @property
    def port(self) -> int:
        return self._port

    @property
    def home_dir(self):
        return self._home_dir

    @property
    def known_hosts(self):
        return self._known_hosts

    @property
    def unknown_hosts(self):
        return self._unknown_hosts

    @property
    def user1_pubkey_file(self):
        return self._user_pub_files[0]

    @property
    def user1_privkey_file(self):
        return self._user_key_files[0]

    @property
    def user2_pubkey_file(self):
        return self._user_pub_files[1]

    @property
    def user2_privkey_file(self):
        return self._user_key_files[1]

    def mk_host_keys(self):
        self._host_key_files = []
        self._host_pub_files = []
        # a known_host file that knows all our test host pubkeys
        with open(self._unknown_hosts, 'w') as fd_unknown, \
             open(self._known_hosts, 'w') as fd_known:
            os.chmod(self._unknown_hosts, stat.S_IRUSR | stat.S_IWUSR)
            os.chmod(self._known_hosts, stat.S_IRUSR | stat.S_IWUSR)
            for alg in self._key_algs:
                key_file = os.path.join(self._sshd_dir, f'ssh_host_{alg}_key')
                if not os.path.exists(key_file):
                    p = subprocess.run(args=[
                        self._keygen, '-q', '-N', '', '-t', alg, '-f', key_file
                    ], capture_output=True, text=True)
                    if p.returncode != 0:
                        raise RuntimeError(f'error generating host key {key_file}: {p.returncode}')
                self._host_key_files.append(key_file)
                pub_file = f'{key_file}.pub'
                self._host_pub_files.append(pub_file)
                pubkey = open(pub_file).read()
                # fd_known.write(f'[127.0.0.1]:{self.port} {pubkey}')
                fd_known.write(f'[{self.env.domain1.lower()}]:{self.port} {pubkey}')
                fd_unknown.write(f'dummy.invalid {pubkey}')
        # hash the known_hosts file, libssh requires it
        p = subprocess.run(args=[
            self._keygen, '-H', '-f', self._known_hosts
        ], capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f'error hashing {self._known_hosts}: {p.returncode}')

    def mk_user_keys(self):
        self._user_key_files = []
        self._user_pub_files = []
        alg = 'rsa'
        for user in self._users:
            key_file = os.path.join(self._sshd_dir, f'id_{user}_user_{alg}_key')
            if not os.path.exists(key_file):
                p = subprocess.run(args=[
                    self._keygen, '-q', '-N', '', '-t', alg, '-f', key_file
                ], capture_output=True, text=True)
                if p.returncode != 0:
                    raise RuntimeError(f'error generating user key {key_file}: {p.returncode}')
            self._user_key_files.append(key_file)
            self._user_pub_files.append(f'{key_file}.pub')
        with open(self._auth_keys, 'w') as fd:
            os.chmod(self._auth_keys, stat.S_IRUSR | stat.S_IWUSR)
            pubkey = open(self._user_pub_files[0]).read()
            fd.write(pubkey)

    def clear_logs(self):
        self._rmf(self._sshd_log)

    def dump_log(self):
        lines = ['>>--sshd log ----------------------------------------------\n']
        lines.extend(open(self._sshd_log))
        lines.extend(['>>--curl log ----------------------------------------------\n'])
        lines.extend(open(os.path.join(self._tmp_dir, 'curl.stderr')))
        lines.append('<<-------------------------------------------------------\n')
        return ''.join(lines)

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
            self.mk_host_keys()
            self.mk_user_keys()
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
            '-D',
            '-f', f'{self._conf_file}',
            '-E', f'{self._sshd_log}',
        ]
        run_env = os.environ.copy()
        # does not have any effect, sadly
        # run_env['HOME'] = f'{self._home_dir}'
        procerr = open(self._sshd_log, 'a')
        self._process = subprocess.Popen(args=args, stderr=procerr, env=run_env)
        if self._process.returncode is not None:
            return False
        return self.wait_live(timeout=timedelta(seconds=Env.SERVER_TIMEOUT))

    def wait_live(self, timeout: timedelta):
        curl = CurlClient(env=self.env, run_dir=self._tmp_dir,
                          timeout=timeout.total_seconds())
        try_until = datetime.now() + timeout
        while datetime.now() < try_until:
            r = curl.http_get(url=f'scp://{self.env.domain1}:{self._port}/{self.home_dir}/data',
                              extra_args=[
                                  '--insecure',
                                  '--pubkey', self.user1_pubkey_file,
                                  '--key', self.user1_privkey_file,
                                  '--user', f'{os.environ["USER"]}:',
                              ])
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        log.error(f"sshd still not responding after {timeout}")
        return False

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _write_config(self):
        conf = [
            f'ListenAddress 127.0.0.1:{self._port}',
            'AllowTcpForwarding yes',
            'AuthenticationMethods publickey',
            'PasswordAuthentication no',
            # in CI, we might run as root, allow this
            'PermitRootLogin yes',
            'LogLevel VERBOSE',
            f'AuthorizedKeysFile {self._auth_keys}',
            f'PidFile {self._pid_file}',
        ]
        conf.extend([f'HostKey {key_file}' for key_file in self._host_key_files])
        if self._sftpd:
            conf.append(f'Subsystem sftp {self._sftpd}')
        conf.append('\n')
        with open(self._conf_file, 'w') as fd:
            fd.write("\n".join(conf))
