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
import shutil
import subprocess
from datetime import datetime
from typing import Optional, Dict

from . import ExecResult
from .env import Env


log = logging.getLogger(__name__)


class LocalClient:

    def __init__(self, name: str, env: Env, run_dir: Optional[str] = None,
                 timeout: Optional[float] = None,
                 run_env: Optional[Dict[str,str]] = None):
        self.name = name
        self.path = os.path.join(env.build_dir, 'tests/client/clients')
        self.env = env
        self._run_env = run_env
        self._timeout = timeout if timeout else env.test_timeout
        self._curl = os.environ['CURL'] if 'CURL' in os.environ else env.curl
        self._run_dir = run_dir if run_dir else os.path.join(env.gen_dir, name)
        self._stdoutfile = f'{self._run_dir}/stdout'
        self._stderrfile = f'{self._run_dir}/stderr'
        self._rmrf(self._run_dir)
        self._mkpath(self._run_dir)

    @property
    def run_dir(self) -> str:
        return self._run_dir

    @property
    def stderr_file(self) -> str:
        return self._stderrfile

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def download_file(self, i: int) -> str:
        return os.path.join(self._run_dir, f'download_{i}.data')

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def run(self, args):
        self._rmf(self._stdoutfile)
        self._rmf(self._stderrfile)
        start = datetime.now()
        exception = None
        myargs = [self.path, self.name]
        myargs.extend(args)
        run_env = None
        if self._run_env:
            run_env = self._run_env.copy()
            for key in ['CURL_DEBUG']:
                if key in os.environ and key not in run_env:
                    run_env[key] = os.environ[key]
        try:
            with open(self._stdoutfile, 'w') as cout, open(self._stderrfile, 'w') as cerr:
                p = subprocess.run(myargs, stderr=cerr, stdout=cout,
                                   cwd=self._run_dir, shell=False,
                                   input=None, env=run_env,
                                   timeout=self._timeout)
                exitcode = p.returncode
        except subprocess.TimeoutExpired:
            log.warning(f'Timeout after {self._timeout}s: {args}')
            exitcode = -1
            exception = 'TimeoutExpired'
        coutput = open(self._stdoutfile).readlines()
        cerrput = open(self._stderrfile).readlines()
        return ExecResult(args=myargs, exit_code=exitcode, exception=exception,
                          stdout=coutput, stderr=cerrput,
                          duration=datetime.now() - start)

    def dump_logs(self):
        lines = []
        lines.append('>>--stdout ----------------------------------------------\n')
        lines.extend(open(self._stdoutfile).readlines())
        lines.append('>>--stderr ----------------------------------------------\n')
        lines.extend(open(self._stderrfile).readlines())
        lines.append('<<-------------------------------------------------------\n')
        return ''.join(lines)
