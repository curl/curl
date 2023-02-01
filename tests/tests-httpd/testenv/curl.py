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
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import timedelta, datetime
from typing import List, Optional, Dict
from urllib.parse import urlparse

from .env import Env


log = logging.getLogger(__name__)


class ExecResult:

    def __init__(self, args: List[str], exit_code: int,
                 stdout: List[str], stderr: List[str],
                 duration: Optional[timedelta] = None,
                 with_stats: bool = False):
        self._args = args
        self._exit_code = exit_code
        self._stdout = stdout
        self._stderr = stderr
        self._duration = duration if duration is not None else timedelta()
        self._response = None
        self._responses = []
        self._results = {}
        self._assets = []
        self._stats = []
        self._json_out = None
        self._with_stats = with_stats
        if with_stats:
            self._parse_stats()
        else:
            # noinspection PyBroadException
            try:
                out = ''.join(self._stdout)
                self._json_out = json.loads(out)
            except:
                pass

    def __repr__(self):
        return f"ExecResult[code={self.exit_code}, args={self._args}, stdout={self._stdout}, stderr={self._stderr}]"

    def _parse_stats(self):
        self._stats = []
        for l in self._stdout:
            try:
                self._stats.append(json.loads(l))
            except:
                log.error(f'not a JSON stat: {l}')
                log.error(f'stdout is: {"".join(self._stdout)}')
                break

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def args(self) -> List[str]:
        return self._args

    @property
    def outraw(self) -> bytes:
        return ''.join(self._stdout).encode()

    @property
    def stdout(self) -> str:
        return ''.join(self._stdout)

    @property
    def json(self) -> Optional[Dict]:
        """Output as JSON dictionary or None if not parseable."""
        return self._json_out

    @property
    def stderr(self) -> str:
        return ''.join(self._stderr)

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def response(self) -> Optional[Dict]:
        return self._response

    @property
    def responses(self) -> List[Dict]:
        return self._responses

    @property
    def results(self) -> Dict:
        return self._results

    @property
    def assets(self) -> List:
        return self._assets

    @property
    def with_stats(self) -> bool:
        return self._with_stats

    @property
    def stats(self) -> List:
        return self._stats

    @property
    def total_connects(self) -> Optional[int]:
        if len(self.stats):
            n = 0
            for stat in self.stats:
                n += stat['num_connects']
            return n
        return None

    def add_response(self, resp: Dict):
        self._response = resp
        self._responses.append(resp)

    def add_results(self, results: Dict):
        self._results.update(results)
        if 'response' in results:
            self.add_response(results['response'])

    def add_assets(self, assets: List):
        self._assets.extend(assets)

    def check_responses(self, count: int, exp_status: Optional[int] = None,
                        exp_exitcode: Optional[int] = None):
        assert len(self.responses) == count, \
            f'response count: expected {count}, got {len(self.responses)}'
        if exp_status is not None:
            for idx, x in enumerate(self.responses):
                assert x['status'] == exp_status, \
                    f'response #{idx} unexpectedstatus: {x["status"]}'
        if exp_exitcode is not None:
            for idx, x in enumerate(self.responses):
                if 'exitcode' in x:
                    assert x['exitcode'] == 0, f'response #{idx} exitcode: {x["exitcode"]}'
        if self.with_stats:
            assert len(self.stats) == count, f'{self}'

    def check_stats(self, count: int, exp_status: Optional[int] = None,
                        exp_exitcode: Optional[int] = None):
        assert len(self.stats) == count, \
            f'stats count: expected {count}, got {len(self.stats)}'
        if exp_status is not None:
            for idx, x in enumerate(self.stats):
                assert 'http_code' in x, \
                    f'status #{idx} reports no http_code'
                assert x['http_code'] == exp_status, \
                    f'status #{idx} unexpected http_code: {x["http_code"]}'
        if exp_exitcode is not None:
            for idx, x in enumerate(self.stats):
                if 'exitcode' in x:
                    assert x['exitcode'] == 0, f'status #{idx} exitcode: {x["exitcode"]}'


class CurlClient:

    ALPN_ARG = {
        'http/0.9': '--http0.9',
        'http/1.0': '--http1.0',
        'http/1.1': '--http1.1',
        'h2': '--http2',
        'h2c': '--http2',
        'h3': '--http3-only',
    }

    def __init__(self, env: Env, run_dir: Optional[str] = None):
        self.env = env
        self._curl = os.environ['CURL'] if 'CURL' in os.environ else env.curl
        self._run_dir = run_dir if run_dir else os.path.join(env.gen_dir, 'curl')
        self._stdoutfile = f'{self._run_dir}/curl.stdout'
        self._stderrfile = f'{self._run_dir}/curl.stderr'
        self._headerfile = f'{self._run_dir}/curl.headers'
        self._tracefile = f'{self._run_dir}/curl.trace'
        self._log_path = f'{self._run_dir}/curl.log'
        self._rmrf(self._run_dir)
        self._mkpath(self._run_dir)

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def http_get(self, url: str, extra_args: Optional[List[str]] = None):
        return self._raw(url, options=extra_args, with_stats=False)

    def http_download(self, urls: List[str],
                      alpn_proto: Optional[str] = None,
                      with_stats: bool = True,
                      with_headers: bool = False,
                      extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '-o', 'download.data',
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=with_headers)

    def http_upload(self, urls: List[str], data: str,
                    alpn_proto: Optional[str] = None,
                    with_stats: bool = True,
                    with_headers: bool = False,
                    extra_args: Optional[List[str]] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '--data-binary', data, '-o', 'download_#1.data',
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=with_headers)

    def response_file(self, idx: int):
        return os.path.join(self._run_dir, f'download_{idx}.data')

    def run_direct(self, args, with_stats: bool = False):
        my_args = [self._curl]
        if with_stats:
            my_args.extend([
                '-w', '%{json}\\n'
            ])
        my_args.extend([
            '-o', 'download.data',
        ])
        my_args.extend(args)
        return self._run(args=my_args, with_stats=with_stats)

    def _run(self, args, intext='', with_stats: bool = False):
        self._rmf(self._stdoutfile)
        self._rmf(self._stderrfile)
        self._rmf(self._headerfile)
        self._rmf(self._tracefile)
        start = datetime.now()
        with open(self._stdoutfile, 'w') as cout:
            with open(self._stderrfile, 'w') as cerr:
                p = subprocess.run(args, stderr=cerr, stdout=cout,
                                   cwd=self._run_dir, shell=False,
                                   input=intext.encode() if intext else None)
        coutput = open(self._stdoutfile).readlines()
        cerrput = open(self._stderrfile).readlines()
        return ExecResult(args=args, exit_code=p.returncode,
                          stdout=coutput, stderr=cerrput,
                          duration=datetime.now() - start,
                          with_stats=with_stats)

    def _raw(self, urls, timeout=10, options=None, insecure=False,
             alpn_proto: Optional[str] = None,
             force_resolve=True,
             with_stats=False,
             with_headers=True):
        args = self._complete_args(
            urls=urls, timeout=timeout, options=options, insecure=insecure,
            alpn_proto=alpn_proto, force_resolve=force_resolve,
            with_headers=with_headers)
        r = self._run(args, with_stats=with_stats)
        if r.exit_code == 0 and with_headers:
            self._parse_headerfile(self._headerfile, r=r)
            if r.json:
                r.response["json"] = r.json
        return r

    def _complete_args(self, urls, timeout=None, options=None,
                       insecure=False, force_resolve=True,
                       alpn_proto: Optional[str] = None,
                       with_headers: bool = True):
        if not isinstance(urls, list):
            urls = [urls]

        args = [self._curl, "-s", "--path-as-is"]
        if with_headers:
            args.extend(["-D", self._headerfile])
        if self.env.verbose > 2:
            args.extend(['--trace', self._tracefile, '--trace-time'])

        for url in urls:
            u = urlparse(urls[0])
            if alpn_proto is not None:
                if alpn_proto not in self.ALPN_ARG:
                    raise Exception(f'unknown ALPN protocol: "{alpn_proto}"')
                args.append(self.ALPN_ARG[alpn_proto])

            if u.scheme == 'http':
                pass
            elif insecure:
                args.append('--insecure')
            elif options and "--cacert" in options:
                pass
            elif u.hostname:
                args.extend(["--cacert", self.env.ca.cert_file])

            if force_resolve and u.hostname and u.hostname != 'localhost' \
                    and not re.match(r'^(\d+|\[|:).*', u.hostname):
                port = u.port if u.port else 443
                args.extend(["--resolve", f"{u.hostname}:{port}:127.0.0.1"])
            if timeout is not None and int(timeout) > 0:
                args.extend(["--connect-timeout", str(int(timeout))])
            if options:
                args.extend(options)
            args.append(url)
        return args

    def _parse_headerfile(self, headerfile: str, r: ExecResult = None) -> ExecResult:
        lines = open(headerfile).readlines()
        if r is None:
            r = ExecResult(args=[], exit_code=0, stdout=[], stderr=[])

        response = None

        def fin_response(resp):
            if resp:
                r.add_response(resp)

        expected = ['status']
        for line in lines:
            line = line.strip()
            if re.match(r'^$', line):
                if 'trailer' in expected:
                    # end of trailers
                    fin_response(response)
                    response = None
                    expected = ['status']
                elif 'header' in expected:
                    # end of header, another status or trailers might follow
                    expected = ['status', 'trailer']
                else:
                    assert False, f"unexpected line: '{line}'"
                continue
            if 'status' in expected:
                # log.debug("reading 1st response line: %s", line)
                m = re.match(r'^(\S+) (\d+)( .*)?$', line)
                if m:
                    fin_response(response)
                    response = {
                        "protocol": m.group(1),
                        "status": int(m.group(2)),
                        "description": m.group(3),
                        "header": {},
                        "trailer": {},
                        "body": r.outraw
                    }
                    expected = ['header']
                    continue
            if 'trailer' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['trailer'][m.group(1).lower()] = m.group(2)
                    continue
            if 'header' in expected:
                m = re.match(r'^([^:]+):\s*(.*)$', line)
                if m:
                    response['header'][m.group(1).lower()] = m.group(2)
                    continue
            assert False, f"unexpected line: '{line}, expected: {expected}'"

        fin_response(response)
        return r

