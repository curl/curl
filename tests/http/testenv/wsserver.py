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
from datetime import datetime, timedelta, timezone
import logging
import os
import shutil
import socket
import subprocess
import time
from typing import Dict

from testenv import CurlClient, Env
from testenv.ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class WsServerError(Exception):
    pass


class WsServer:

    def __init__(self, name, env):
        self.name = name
        self.env = env
        self.run_dir = os.path.join(env.gen_dir, self.name)
        self.err_file = os.path.join(self.run_dir, 'stderr')
        self._rmrf(self.run_dir)
        self._mkpath(self.run_dir)
        self.wsproc = None
        self.cerr = None
        self.port = 0
        if self.name == 'ws_echo':
            self.cmd = os.path.join(env.project_dir,
                                    'tests/http/testenv/ws_echo_server.py')
        elif self.name == 'ws_4frames':
            self.cmd = os.path.join(env.project_dir,
                                    'tests/http/testenv/ws_4frames_server.py')
        else:
            raise WsServerError(f'unknown WsServer name {self.name}')

    def check_alive(self, env, port, timeout=Env.SERVER_TIMEOUT):
        curl = CurlClient(env=env)
        url = f'http://localhost:{port}/'
        end = datetime.now(timezone.utc) + timedelta(seconds=timeout)
        while datetime.now(timezone.utc) < end:
            r = curl.http_download(urls=[url])
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        return False

    def _mkpath(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)

    def startup(self):

        def startup(ports: Dict[str, int]) -> bool:
            self.port = ports[self.name]
            wargs = [self.cmd, '--port', str(self.port)]
            log.info(f'start_ {wargs}')
            self.wsproc = subprocess.Popen(args=wargs,
                                           cwd=self.run_dir,
                                           stderr=self.cerr,
                                           stdout=self.cerr)
            if self.check_alive(self.env, self.port):
                self.env.update_ports(ports)
                return True
            log.error(f'not alive {wargs}')
            self.wsproc.terminate()
            self.wsproc = None
            return False

        self.cerr = open(self.err_file, 'w')  # noqa: SIM115
        port_spec = {
            self.name: socket.SOCK_STREAM
        }
        assert alloc_ports_and_do(port_spec, startup,
                                  self.env.gen_root, max_tries=3)
        assert self.wsproc

    def shutdown(self):
        self.wsproc.terminate()
        self.cerr.close()
