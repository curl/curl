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
import json
import logging
import os
import sys
import time
from threading import Thread

import psutil
import re
import shutil
import subprocess
from statistics import mean, fmean
from datetime import timedelta, datetime
from typing import List, Optional, Dict, Union, Any
from urllib.parse import urlparse

from .env import Env


log = logging.getLogger(__name__)


class RunProfile:

    STAT_KEYS = ['cpu', 'rss', 'vsz']

    @classmethod
    def AverageStats(cls, profiles: List['RunProfile']):
        avg = {}
        stats = [p.stats for p in profiles]
        for key in cls.STAT_KEYS:
            avg[key] = mean([s[key] for s in stats])
        return avg

    def __init__(self, pid: int, started_at: datetime, run_dir):
        self._pid = pid
        self._started_at = started_at
        self._duration = timedelta(seconds=0)
        self._run_dir = run_dir
        self._samples = []
        self._psu = None
        self._stats = None

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def stats(self) -> Optional[Dict[str,Any]]:
        return self._stats

    def sample(self):
        elapsed = datetime.now() - self._started_at
        try:
            if self._psu is None:
                self._psu = psutil.Process(pid=self._pid)
            mem = self._psu.memory_info()
            self._samples.append({
                'time': elapsed,
                'cpu': self._psu.cpu_percent(),
                'vsz': mem.vms,
                'rss': mem.rss,
            })
        except psutil.NoSuchProcess:
            pass

    def finish(self):
        self._duration = datetime.now() - self._started_at
        if len(self._samples) > 0:
            weights = [s['time'].total_seconds() for s in self._samples]
            self._stats = {}
            for key in self.STAT_KEYS:
                self._stats[key] = fmean([s[key] for s in self._samples], weights)
        else:
            self._stats = None
        self._psu = None

    def __repr__(self):
        return f'RunProfile[pid={self._pid}, '\
               f'duration={self.duration.total_seconds():.3f}s, '\
               f'stats={self.stats}]'


class RunTcpDump:

    def __init__(self, env, run_dir):
        self._env = env
        self._run_dir = run_dir
        self._proc = None
        self._stdoutfile = os.path.join(self._run_dir, 'tcpdump.out')
        self._stderrfile = os.path.join(self._run_dir, 'tcpdump.err')

    @property
    def stats(self) -> Optional[List[str]]:
        if self._proc:
            raise Exception('tcpdump still running')
        lines = []
        for l in open(self._stdoutfile).readlines():
            if re.match(r'.* IP 127\.0\.0\.1\.\d+ [<>] 127\.0\.0\.1\.\d+:.*', l):
                lines.append(l)
        return lines

    def stats_excluding(self, src_port) -> Optional[List[str]]:
        if self._proc:
            raise Exception('tcpdump still running')
        lines = []
        for l in self.stats:
            if not re.match(r'.* IP 127\.0\.0\.1\.' + str(src_port) + ' >.*', l):
                lines.append(l)
        return lines

    @property
    def stderr(self) -> List[str]:
        if self._proc:
            raise Exception('tcpdump still running')
        lines = []
        return open(self._stderrfile).readlines()

    def sample(self):
        # not sure how to make that detection reliable for all platforms
        local_if = 'lo0' if sys.platform.startswith('darwin') else 'lo'
        try:
            tcpdump = self._env.tcpdump()
            if tcpdump is None:
                raise Exception('tcpdump not available')
            # look with tcpdump for TCP RST packets which indicate
            # we did not shut down connections cleanly
            args = []
            # at least on Linux, we need root permissions to run tcpdump
            if sys.platform.startswith('linux'):
                args.append('sudo')
            args.extend([
                tcpdump, '-i', local_if, '-n', 'tcp[tcpflags] & (tcp-rst)!=0'
            ])
            with open(self._stdoutfile, 'w') as cout:
                with open(self._stderrfile, 'w') as cerr:
                    self._proc = subprocess.Popen(args, stdout=cout, stderr=cerr,
                                                  text=True, cwd=self._run_dir,
                                                  shell=False)
                    assert self._proc
                    assert self._proc.returncode is None
                    while self._proc:
                        try:
                            self._proc.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
        except Exception as e:
            log.error(f'Tcpdump: {e}')

    def start(self):
        def do_sample():
            self.sample()
        t = Thread(target=do_sample)
        t.start()

    def finish(self):
        if self._proc:
            time.sleep(1)
            self._proc.terminate()
            self._proc = None


class ExecResult:

    def __init__(self, args: List[str], exit_code: int,
                 stdout: List[str], stderr: List[str],
                 duration: Optional[timedelta] = None,
                 with_stats: bool = False,
                 exception: Optional[str] = None,
                 profile: Optional[RunProfile] = None,
                 tcpdump: Optional[RunTcpDump] = None):
        self._args = args
        self._exit_code = exit_code
        self._exception = exception
        self._stdout = stdout
        self._stderr = stderr
        self._profile = profile
        self._tcpdump = tcpdump
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
        return f"ExecResult[code={self.exit_code}, exception={self._exception}, "\
               f"args={self._args}, stdout={self._stdout}, stderr={self._stderr}]"

    def _parse_stats(self):
        self._stats = []
        for l in self._stdout:
            try:
                self._stats.append(json.loads(l))
            except:
                log.error(f'not a JSON stat: {l}')
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
    def trace_lines(self) -> List[str]:
        return self._stderr

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def profile(self) -> Optional[RunProfile]:
        return self._profile

    @property
    def tcpdump(self) -> Optional[RunTcpDump]:
        return self._tcpdump

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

    def check_exit_code(self, code: Union[int, bool]):
        if code is True:
            assert self.exit_code == 0, f'expected exit code {code}, '\
                                        f'got {self.exit_code}\n{self.dump_logs()}'
        elif code is False:
            assert self.exit_code != 0, f'expected exit code {code}, '\
                                                f'got {self.exit_code}\n{self.dump_logs()}'
        else:
            assert self.exit_code == code, f'expected exit code {code}, '\
                                           f'got {self.exit_code}\n{self.dump_logs()}'

    def check_response(self, http_status: Optional[int] = 200,
                       count: Optional[int] = 1,
                       protocol: Optional[str] = None,
                       exitcode: Optional[int] = 0,
                       connect_count: Optional[int] = None):
        if exitcode:
            self.check_exit_code(exitcode)
            if self.with_stats and isinstance(exitcode, int):
                for idx, x in enumerate(self.stats):
                    if 'exitcode' in x:
                        assert int(x['exitcode']) == exitcode, \
                            f'response #{idx} exitcode: expected {exitcode}, '\
                            f'got {x["exitcode"]}\n{self.dump_logs()}'

        if self.with_stats:
            assert len(self.stats) == count, \
                f'response count: expected {count}, ' \
                f'got {len(self.stats)}\n{self.dump_logs()}'
        else:
            assert len(self.responses) == count, \
                f'response count: expected {count}, ' \
                f'got {len(self.responses)}\n{self.dump_logs()}'
        if http_status is not None:
            if self.with_stats:
                for idx, x in enumerate(self.stats):
                    assert 'http_code' in x, \
                        f'response #{idx} reports no http_code\n{self.dump_stat(x)}'
                    assert x['http_code'] == http_status, \
                        f'response #{idx} http_code: expected {http_status}, '\
                        f'got {x["http_code"]}\n{self.dump_stat(x)}'
            else:
                for idx, x in enumerate(self.responses):
                    assert x['status'] == http_status, \
                        f'response #{idx} status: expected {http_status},'\
                        f'got {x["status"]}\n{self.dump_stat(x)}'
        if protocol is not None:
            if self.with_stats:
                http_version = None
                if protocol == 'HTTP/1.1':
                    http_version = '1.1'
                elif protocol == 'HTTP/2':
                    http_version = '2'
                elif protocol == 'HTTP/3':
                    http_version = '3'
                if http_version is not None:
                    for idx, x in enumerate(self.stats):
                        assert x['http_version'] == http_version, \
                            f'response #{idx} protocol: expected http/{http_version},' \
                            f'got version {x["http_version"]}\n{self.dump_stat(x)}'
            else:
                for idx, x in enumerate(self.responses):
                    assert x['protocol'] == protocol, \
                        f'response #{idx} protocol: expected {protocol},'\
                        f'got {x["protocol"]}\n{self.dump_logs()}'
        if connect_count is not None:
            assert self.total_connects == connect_count, \
                f'expected {connect_count}, but {self.total_connects} '\
                f'were made\n{self.dump_logs()}'

    def check_stats(self, count: int, http_status: Optional[int] = None,
                    exitcode: Optional[int] = None):
        if exitcode is None:
            self.check_exit_code(0)
        assert len(self.stats) == count, \
            f'stats count: expected {count}, got {len(self.stats)}\n{self.dump_logs()}'
        if http_status is not None:
            for idx, x in enumerate(self.stats):
                assert 'http_code' in x, \
                    f'status #{idx} reports no http_code\n{self.dump_stat(x)}'
                assert x['http_code'] == http_status, \
                    f'status #{idx} http_code: expected {http_status}, '\
                    f'got {x["http_code"]}\n{self.dump_stat(x)}'
        if exitcode is not None:
            for idx, x in enumerate(self.stats):
                if 'exitcode' in x:
                    assert x['exitcode'] == exitcode, \
                        f'status #{idx} exitcode: expected {exitcode}, '\
                        f'got {x["exitcode"]}\n{self.dump_stat(x)}'

    def dump_logs(self):
        lines = ['>>--stdout ----------------------------------------------\n']
        lines.extend(self._stdout)
        lines.append('>>--stderr ----------------------------------------------\n')
        lines.extend(self._stderr)
        lines.append('<<-------------------------------------------------------\n')
        return ''.join(lines)

    def dump_stat(self, x):
        lines = [
            'json stat from curl:',
            json.JSONEncoder(indent=2).encode(x),
        ]
        if 'xfer_id' in x:
            xfer_id = x['xfer_id']
            lines.append(f'>>--xfer {xfer_id} trace:\n')
            lines.extend(self.xfer_trace_for(xfer_id))
        else:
            lines.append('>>--full trace-------------------------------------------\n')
            lines.extend(self._stderr)
            lines.append('<<-------------------------------------------------------\n')
        return ''.join(lines)

    def xfer_trace_for(self, xfer_id) -> List[str]:
            pat = re.compile(f'^[^[]* \\[{xfer_id}-.*$')
            return [line for line in self._stderr if pat.match(line)]


class CurlClient:

    ALPN_ARG = {
        'http/0.9': '--http0.9',
        'http/1.0': '--http1.0',
        'http/1.1': '--http1.1',
        'h2': '--http2',
        'h2c': '--http2',
        'h3': '--http3-only',
    }

    def __init__(self, env: Env,
                 run_dir: Optional[str] = None,
                 timeout: Optional[float] = None,
                 silent: bool = False,
                 run_env: Optional[Dict[str, str]] = None):
        self.env = env
        self._timeout = timeout if timeout else env.test_timeout
        self._curl = os.environ['CURL'] if 'CURL' in os.environ else env.curl
        self._run_dir = run_dir if run_dir else os.path.join(env.gen_dir, 'curl')
        self._stdoutfile = f'{self._run_dir}/curl.stdout'
        self._stderrfile = f'{self._run_dir}/curl.stderr'
        self._headerfile = f'{self._run_dir}/curl.headers'
        self._log_path = f'{self._run_dir}/curl.log'
        self._silent = silent
        self._run_env = run_env
        self._rmrf(self._run_dir)
        self._mkpath(self._run_dir)

    @property
    def run_dir(self) -> str:
        return self._run_dir

    def download_file(self, i: int) -> str:
        return os.path.join(self.run_dir, f'download_{i}.data')

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def get_proxy_args(self, proto: str = 'http/1.1',
                       proxys: bool = True, tunnel: bool = False,
                       use_ip: bool = False):
        proxy_name = '127.0.0.1' if use_ip else self.env.proxy_domain
        if proxys:
            pport = self.env.pts_port(proto) if tunnel else self.env.proxys_port
            xargs = [
                '--proxy', f'https://{proxy_name}:{pport}/',
                '--resolve', f'{proxy_name}:{pport}:127.0.0.1',
                '--proxy-cacert', self.env.ca.cert_file,
            ]
            if proto == 'h2':
                xargs.append('--proxy-http2')
        else:
            xargs = [
                '--proxy', f'http://{proxy_name}:{self.env.proxy_port}/',
                '--resolve', f'{proxy_name}:{self.env.proxy_port}:127.0.0.1',
            ]
        if tunnel:
            xargs.append('--proxytunnel')
        return xargs

    def http_get(self, url: str, extra_args: Optional[List[str]] = None,
                 alpn_proto: Optional[str] = None,
                 def_tracing: bool = True,
                 with_stats: bool = False,
                 with_profile: bool = False,
                 with_tcpdump: bool = False):
        return self._raw(url, options=extra_args,
                         with_stats=with_stats,
                         alpn_proto=alpn_proto,
                         def_tracing=def_tracing,
                         with_profile=with_profile,
                         with_tcpdump=with_tcpdump)

    def http_download(self, urls: List[str],
                      alpn_proto: Optional[str] = None,
                      with_stats: bool = True,
                      with_headers: bool = False,
                      with_profile: bool = False,
                      with_tcpdump: bool = False,
                      no_save: bool = False,
                      extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        if no_save:
            extra_args.extend([
                '-o', '/dev/null',
            ])
        else:
            extra_args.extend([
                '-o', 'download_#1.data',
            ])
        # remove any existing ones
        for i in range(100):
            self._rmf(self.download_file(i))
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=with_headers,
                         with_profile=with_profile,
                         with_tcpdump=with_tcpdump)

    def http_upload(self, urls: List[str], data: str,
                    alpn_proto: Optional[str] = None,
                    with_stats: bool = True,
                    with_headers: bool = False,
                    with_profile: bool = False,
                    with_tcpdump: bool = False,
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
                         with_headers=with_headers,
                         with_profile=with_profile,
                         with_tcpdump=with_tcpdump)

    def http_delete(self, urls: List[str],
                    alpn_proto: Optional[str] = None,
                    with_stats: bool = True,
                    with_profile: bool = False,
                    extra_args: Optional[List[str]] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '-X', 'DELETE', '-o', '/dev/null',
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=False,
                         with_profile=with_profile)

    def http_put(self, urls: List[str], data=None, fdata=None,
                 alpn_proto: Optional[str] = None,
                 with_stats: bool = True,
                 with_headers: bool = False,
                 with_profile: bool = False,
                 extra_args: Optional[List[str]] = None):
        if extra_args is None:
            extra_args = []
        if fdata is not None:
            extra_args.extend(['-T', fdata])
        elif data is not None:
            extra_args.extend(['-T', '-'])
        extra_args.extend([
            '-o', 'download_#1.data',
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, intext=data,
                         alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=with_headers,
                         with_profile=with_profile)

    def http_form(self, urls: List[str], form: Dict[str, str],
                  alpn_proto: Optional[str] = None,
                  with_stats: bool = True,
                  with_headers: bool = False,
                  extra_args: Optional[List[str]] = None):
        if extra_args is None:
            extra_args = []
        for key, val in form.items():
            extra_args.extend(['-F', f'{key}={val}'])
        extra_args.extend([
            '-o', 'download_#1.data',
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, alpn_proto=alpn_proto, options=extra_args,
                         with_stats=with_stats,
                         with_headers=with_headers)

    def ftp_get(self, urls: List[str],
                      with_stats: bool = True,
                      with_profile: bool = False,
                      with_tcpdump: bool = False,
                      no_save: bool = False,
                      extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        if no_save:
            extra_args.extend([
                '-o', '/dev/null',
            ])
        else:
            extra_args.extend([
                '-o', 'download_#1.data',
            ])
        # remove any existing ones
        for i in range(100):
            self._rmf(self.download_file(i))
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, options=extra_args,
                         with_stats=with_stats,
                         with_headers=False,
                         with_profile=with_profile,
                         with_tcpdump=with_tcpdump)

    def ftp_ssl_get(self, urls: List[str],
                      with_stats: bool = True,
                      with_profile: bool = False,
                      with_tcpdump: bool = False,
                      no_save: bool = False,
                      extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '--ssl-reqd',
        ])
        return self.ftp_get(urls=urls, with_stats=with_stats,
                            with_profile=with_profile, no_save=no_save,
                            with_tcpdump=with_tcpdump,
                            extra_args=extra_args)

    def ftp_upload(self, urls: List[str], fupload,
                   with_stats: bool = True,
                   with_profile: bool = False,
                   with_tcpdump: bool = False,
                   extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '--upload-file', fupload
        ])
        if with_stats:
            extra_args.extend([
                '-w', '%{json}\\n'
            ])
        return self._raw(urls, options=extra_args,
                         with_stats=with_stats,
                         with_headers=False,
                         with_profile=with_profile,
                         with_tcpdump=with_tcpdump)

    def ftp_ssl_upload(self, urls: List[str], fupload,
                       with_stats: bool = True,
                       with_profile: bool = False,
                       with_tcpdump: bool = False,
                       extra_args: List[str] = None):
        if extra_args is None:
            extra_args = []
        extra_args.extend([
            '--ssl-reqd',
        ])
        return self.ftp_upload(urls=urls, fupload=fupload,
                               with_stats=with_stats, with_profile=with_profile,
                               with_tcpdump=with_tcpdump,
                               extra_args=extra_args)

    def response_file(self, idx: int):
        return os.path.join(self._run_dir, f'download_{idx}.data')

    def run_direct(self, args, with_stats: bool = False, with_profile: bool = False):
        my_args = [self._curl]
        if with_stats:
            my_args.extend([
                '-w', '%{json}\\n'
            ])
        my_args.extend([
            '-o', 'download.data',
        ])
        my_args.extend(args)
        return self._run(args=my_args, with_stats=with_stats, with_profile=with_profile)

    def _run(self, args, intext='', with_stats: bool = False,
             with_profile: bool = True, with_tcpdump: bool = False):
        self._rmf(self._stdoutfile)
        self._rmf(self._stderrfile)
        self._rmf(self._headerfile)
        exception = None
        profile = None
        tcpdump = None
        started_at = datetime.now()
        if with_tcpdump:
            tcpdump = RunTcpDump(self.env, self._run_dir)
            tcpdump.start()
        try:
            with open(self._stdoutfile, 'w') as cout:
                with open(self._stderrfile, 'w') as cerr:
                    if with_profile:
                        end_at = started_at + timedelta(seconds=self._timeout) \
                            if self._timeout else None
                        log.info(f'starting: {args}')
                        p = subprocess.Popen(args, stderr=cerr, stdout=cout,
                                             cwd=self._run_dir, shell=False,
                                             env=self._run_env)
                        profile = RunProfile(p.pid, started_at, self._run_dir)
                        if intext is not None and False:
                            p.communicate(input=intext.encode(), timeout=1)
                        ptimeout = 0.0
                        while True:
                            try:
                                p.wait(timeout=ptimeout)
                                break
                            except subprocess.TimeoutExpired:
                                if end_at and datetime.now() >= end_at:
                                    p.kill()
                                    raise subprocess.TimeoutExpired(cmd=args, timeout=self._timeout)
                                profile.sample()
                                ptimeout = 0.01
                        exitcode = p.returncode
                        profile.finish()
                        log.info(f'done: exit={exitcode}, profile={profile}')
                    else:
                        p = subprocess.run(args, stderr=cerr, stdout=cout,
                                           cwd=self._run_dir, shell=False,
                                           input=intext.encode() if intext else None,
                                           timeout=self._timeout,
                                           env=self._run_env)
                        exitcode = p.returncode
        except subprocess.TimeoutExpired:
            now = datetime.now()
            duration = now - started_at
            log.warning(f'Timeout at {now} after {duration.total_seconds()}s '
                        f'(configured {self._timeout}s): {args}')
            exitcode = -1
            exception = 'TimeoutExpired'
        if tcpdump:
            tcpdump.finish()
        coutput = open(self._stdoutfile).readlines()
        cerrput = open(self._stderrfile).readlines()
        return ExecResult(args=args, exit_code=exitcode, exception=exception,
                          stdout=coutput, stderr=cerrput,
                          duration=datetime.now() - started_at,
                          with_stats=with_stats,
                          profile=profile, tcpdump=tcpdump)

    def _raw(self, urls, intext='', timeout=None, options=None, insecure=False,
             alpn_proto: Optional[str] = None,
             force_resolve=True,
             with_stats=False,
             with_headers=True,
             def_tracing=True,
             with_profile=False,
             with_tcpdump=False):
        args = self._complete_args(
            urls=urls, timeout=timeout, options=options, insecure=insecure,
            alpn_proto=alpn_proto, force_resolve=force_resolve,
            with_headers=with_headers, def_tracing=def_tracing)
        r = self._run(args, intext=intext, with_stats=with_stats,
                      with_profile=with_profile, with_tcpdump=with_tcpdump)
        if r.exit_code == 0 and with_headers:
            self._parse_headerfile(self._headerfile, r=r)
            if r.json:
                r.response["json"] = r.json
        return r

    def _complete_args(self, urls, timeout=None, options=None,
                       insecure=False, force_resolve=True,
                       alpn_proto: Optional[str] = None,
                       with_headers: bool = True,
                       def_tracing: bool = True):
        if not isinstance(urls, list):
            urls = [urls]

        args = [self._curl, "-s", "--path-as-is"]
        if with_headers:
            args.extend(["-D", self._headerfile])
        if def_tracing is not False and not self._silent:
            args.extend(['-v', '--trace-ids', '--trace-time'])
            if self.env.verbose > 1:
                args.extend(['--trace-config', 'http/2,http/3,h2-proxy,h1-proxy'])
                pass

        active_options = options
        if options is not None and '--next' in options:
            active_options = options[options.index('--next') + 1:]

        for url in urls:
            u = urlparse(urls[0])
            if options:
                args.extend(options)
            if alpn_proto is not None:
                if alpn_proto not in self.ALPN_ARG:
                    raise Exception(f'unknown ALPN protocol: "{alpn_proto}"')
                args.append(self.ALPN_ARG[alpn_proto])

            if u.scheme == 'http':
                pass
            elif insecure:
                args.append('--insecure')
            elif active_options and "--cacert" in active_options:
                pass
            elif u.hostname:
                args.extend(["--cacert", self.env.ca.cert_file])

            if force_resolve and u.hostname and u.hostname != 'localhost' \
                    and not re.match(r'^(\d+|\[|:).*', u.hostname):
                port = u.port if u.port else 443
                args.extend(["--resolve", f"{u.hostname}:{port}:127.0.0.1"])
            if timeout is not None and int(timeout) > 0:
                args.extend(["--connect-timeout", str(int(timeout))])
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
