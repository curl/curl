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
import datetime
import logging
import os
import signal
import subprocess
import time
from typing import Optional

from .env import Env


log = logging.getLogger(__name__)


class Nghttpx:

    def __init__(self, env: Env):
        self.env = env
        self._cmd = env.nghttpx
        self._pid_file = os.path.join(env.gen_dir, 'nghttpx.pid')
        self._conf_file = os.path.join(env.gen_dir, 'nghttpx.conf')
        self._error_log = os.path.join(env.gen_dir, 'nghttpx.log')
        self._stderr = os.path.join(env.gen_dir, 'nghttpx.stderr')
        self._process = None
        self._process: Optional[subprocess.Popen] = None

    def exists(self):
        return os.path.exists(self._cmd)

    def clear_logs(self):
        self._rmf(self._error_log)
        self._rmf(self._stderr)

    def is_running(self):
        if self._process:
            self._process.poll()
            return self._process.returncode is None
        return False

    def start(self):
        if self._process:
            self.stop()
        self._write_config()
        args = [
            self._cmd,
            f'--frontend=*,{self.env.h3_port};quic',
            f'--backend=127.0.0.1,{self.env.https_port};{self.env.domain1};sni={self.env.domain1};proto=h2;tls',
            f'--backend=127.0.0.1,{self.env.http_port}',
            f'--log-level=INFO',
            f'--pid-file={self._pid_file}',
            f'--errorlog-file={self._error_log}',
            f'--conf={self._conf_file}',
            f'--cacert={self.env.ca.cert_file}',
            self.env.get_credentials(self.env.domain1).pkey_file,
            self.env.get_credentials(self.env.domain1).cert_file,
        ]
        ngerr = open(self._stderr, 'a')
        self._process = subprocess.Popen(args=args, stderr=ngerr)
        return self._process.returncode is None

    def stop(self):
        if self._process:
            self._process.terminate()
            self._process.wait(timeout=2)
            self._process = None
        return True

    def restart(self):
        self.stop()
        return self.start()

    def reload(self, timeout: datetime.timedelta):
        if self._process:
            running = self._process
            os.kill(running.pid, signal.SIGQUIT)
            self.start()
            try:
                log.debug(f'waiting for nghttpx({running.pid}) to exit.')
                running.wait(timeout=timeout.seconds)
                log.debug(f'nghttpx({running.pid}) terminated -> {running.returncode}')
                return True
            except subprocess.TimeoutExpired:
                log.error(f'SIGQUIT nghttpx({running.pid}), but did not shut down.')
        return False

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _write_config(self):
        with open(self._conf_file, 'w') as fd:
            fd.write(f'# nghttpx test config'),
            fd.write("\n".join([
                '# do we need something here?'
            ]))
