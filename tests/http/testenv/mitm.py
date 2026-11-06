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
import select
import shutil
import socket
import time
from threading import Thread
from typing import Dict

from testenv.ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class MitmServerError(Exception):
    pass


class MitmServer:

    def __init__(self, name, env, dest_port, fwd_limit = 0):
        self.name = name
        self.env = env
        self.dest_port = dest_port
        self.fwd_limit = fwd_limit
        self.run_dir = os.path.join(env.gen_dir, self.name)
        self.err_file = os.path.join(self.run_dir, 'stderr')
        self._rmrf(self.run_dir)
        self._mkpath(self.run_dir)
        self.thread = None
        self.cerr = None
        self.port = 0
        self.abort = False

    def _mkpath(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)

    def _run_server(self):
        listener = socket.create_server(("127.0.0.1", self.port))
        self.cerr.write(f"listening on {self.port}\n")
        listener.settimeout(0.2)
        while not self.abort:
            try:
                client, _ = listener.accept()
                self.cerr.write(f"accepted connection, opening socket to {self.dest_port}\n")
                server = socket.create_connection(("127.0.0.1", self.dest_port))

                forwarded = swallowed = 0
                client_last_heard = time.time()

                while not (swallowed and time.time() - client_last_heard > 1) and not self.abort:
                    readable, _, errors = select.select([client, server], [], [client, server], 0.2)
                    if len(errors):
                        break
                    if client in readable:
                        data = client.recv(65536)
                        if not data:
                            break
                        client_last_heard = time.time()
                        self.cerr.write(f"client -> {len(data)} bytes\n")
                        if self.fwd_limit:
                            passed_on = data[:max(0, self.fwd_limit - forwarded)]
                        else:
                            passed_on = data
                        self.cerr.write(f"client -> {len(data)} bytes, pass {len(passed_on)}\n")
                        server.sendall(passed_on)
                        forwarded += len(passed_on)
                        swallowed += len(data) - len(passed_on)
                    if server in readable:
                        data = server.recv(65536)
                        if not data:
                            break
                        self.cerr.write(f"server -> {len(data)} bytes\n")
                        client.sendall(data)

                client.close()
                server.close()
                self.cerr.write(f"terminating client, aborted={self.abort}\n")
            except TimeoutError:
                pass

        listener.close()

    def startup(self):

        def startup(ports: Dict[str, int]) -> bool:
            self.port = ports[self.name]

            def run_server():
                self._run_server()

            self.cerr.write(f"starting with port {self.port}\n")
            self.thread = Thread(target=run_server)
            self.thread.start()
            return True

        self.cerr = open(self.err_file, 'w')  # noqa: SIM115
        port_spec = {
            self.name: socket.SOCK_STREAM
        }
        assert alloc_ports_and_do(port_spec, startup,
                                  self.env.gen_root, max_tries=3)
        assert self.thread

    def shutdown(self):
        self.abort = True
        if self.thread:
            self.thread.join()
        self.cerr.close()
