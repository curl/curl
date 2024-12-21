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
import argparse
import json
import logging
import os
import re
import sys
from statistics import mean
from typing import Dict, Any, Optional, List

from testenv import Env, Httpd, CurlClient, Caddy, ExecResult, NghttpxQuic, RunProfile

log = logging.getLogger(__name__)


class ScoreCardError(Exception):
    pass


class ScoreCard:

    def __init__(self, env: Env,
                 protocol: str,
                 server_descr: str,
                 server_port: int,
                 verbose: int,
                 curl_verbose: int,
                 download_parallel: int = 0,
                 server_addr: Optional[str] = None):
        self.verbose = verbose
        self.env = env
        self.protocol = protocol
        self.server_descr = server_descr
        self.server_addr = server_addr
        self.server_port = server_port
        self._silent_curl = not curl_verbose
        self._download_parallel = download_parallel

    def info(self, msg):
        if self.verbose > 0:
            sys.stderr.write(msg)
            sys.stderr.flush()

    def handshakes(self) -> Dict[str, Any]:
        props = {}
        sample_size = 5
        self.info('TLS Handshake\n')
        for authority in [
            'curl.se', 'google.com', 'cloudflare.com', 'nghttp2.org'
        ]:
            self.info(f'  {authority}...')
            props[authority] = {}
            for ipv in ['ipv4', 'ipv6']:
                self.info(f'{ipv}...')
                c_samples = []
                hs_samples = []
                errors = []
                for _ in range(sample_size):
                    curl = CurlClient(env=self.env, silent=self._silent_curl,
                                      server_addr=self.server_addr)
                    args = [
                        '--http3-only' if self.protocol == 'h3' else '--http2',
                        f'--{ipv}', f'https://{authority}/'
                    ]
                    r = curl.run_direct(args=args, with_stats=True)
                    if r.exit_code == 0 and len(r.stats) == 1:
                        c_samples.append(r.stats[0]['time_connect'])
                        hs_samples.append(r.stats[0]['time_appconnect'])
                    else:
                        errors.append(f'exit={r.exit_code}')
                    props[authority][f'{ipv}-connect'] = mean(c_samples) \
                        if len(c_samples) else -1
                    props[authority][f'{ipv}-handshake'] = mean(hs_samples) \
                        if len(hs_samples) else -1
                    props[authority][f'{ipv}-errors'] = errors
            self.info('ok.\n')
        return props

    def _make_docs_file(self, docs_dir: str, fname: str, fsize: int):
        fpath = os.path.join(docs_dir, fname)
        data1k = 1024*'x'
        flen = 0
        with open(fpath, 'w') as fd:
            while flen < fsize:
                fd.write(data1k)
                flen += len(data1k)
        return fpath

    def setup_resources(self, server_docs: str,
                        downloads: Optional[List[int]] = None):
        for fsize in downloads:
            label = self.fmt_size(fsize)
            fname = f'score{label}.data'
            self._make_docs_file(docs_dir=server_docs,
                                 fname=fname, fsize=fsize)
        self._make_docs_file(docs_dir=server_docs,
                             fname='reqs10.data', fsize=10*1024)

    def _check_downloads(self, r: ExecResult, count: int):
        error = ''
        if r.exit_code != 0:
            error += f'exit={r.exit_code} '
        if r.exit_code != 0 or len(r.stats) != count:
            error += f'stats={len(r.stats)}/{count} '
        fails = [s for s in r.stats if s['response_code'] != 200]
        if len(fails) > 0:
            error += f'{len(fails)} failed'
        return error if len(error) > 0 else None

    def transfer_single(self, url: str, count: int):
        sample_size = count
        count = 1
        samples = []
        errors = []
        profiles = []
        self.info('single...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True, with_headers=False,
                                   with_profile=True)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': 1,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles),
        }

    def transfer_serial(self, url: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        profiles = []
        url = f'{url}?[0-{count - 1}]'
        self.info('serial...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True,
                                   with_headers=False, with_profile=True)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': 1,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles),
        }

    def transfer_parallel(self, url: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        profiles = []
        max_parallel = self._download_parallel if self._download_parallel > 0 else count
        url = f'{url}?[0-{count - 1}]'
        self.info('parallel...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True,
                                   with_headers=False,
                                   with_profile=True,
                                   extra_args=[
                                       '--parallel',
                                       '--parallel-max', str(max_parallel)
                                   ])
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': max_parallel,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles),
        }

    def download_url(self, label: str, url: str, count: int):
        self.info(f'  {count}x{label}: ')
        props = {
            'single': self.transfer_single(url=url, count=10),
        }
        if count > 1:
            props['serial'] = self.transfer_serial(url=url, count=count)
            props['parallel'] = self.transfer_parallel(url=url, count=count)
        self.info('ok.\n')
        return props

    def downloads(self, count: int, fsizes: List[int]) -> Dict[str, Any]:
        scores = {}
        for fsize in fsizes:
            label = self.fmt_size(fsize)
            fname = f'score{label}.data'
            url = f'https://{self.env.domain1}:{self.server_port}/{fname}'
            scores[label] = self.download_url(label=label, url=url, count=count)
        return scores

    def _check_uploads(self, r: ExecResult, count: int):
        error = ''
        if r.exit_code != 0:
            error += f'exit={r.exit_code} '
        if r.exit_code != 0 or len(r.stats) != count:
            error += f'stats={len(r.stats)}/{count} '
        fails = [s for s in r.stats if s['response_code'] != 200]
        if len(fails) > 0:
            error += f'{len(fails)} failed'
        for f in fails:
            error += f'[{f["response_code"]}]'
        return error if len(error) > 0 else None

    def upload_single(self, url: str, fpath: str, count: int):
        sample_size = count
        count = 1
        samples = []
        errors = []
        profiles = []
        self.info('single...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_put(urls=[url], fdata=fpath, alpn_proto=self.protocol,
                              with_headers=False, with_profile=True)
            err = self._check_uploads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_upload'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': 1,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles) if len(profiles) else {},
        }

    def upload_serial(self, url: str, fpath: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        profiles = []
        url = f'{url}?id=[0-{count - 1}]'
        self.info('serial...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_put(urls=[url], fdata=fpath, alpn_proto=self.protocol,
                              with_headers=False, with_profile=True)
            err = self._check_uploads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_upload'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': 1,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles) if len(profiles) else {},
        }

    def upload_parallel(self, url: str, fpath: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        profiles = []
        max_parallel = count
        url = f'{url}?id=[0-{count - 1}]'
        self.info('parallel...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_put(urls=[url], fdata=fpath, alpn_proto=self.protocol,
                              with_headers=False, with_profile=True,
                              extra_args=[
                                   '--parallel',
                                    '--parallel-max', str(max_parallel)
                              ])
            err = self._check_uploads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_upload'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'max-parallel': max_parallel,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles) if len(profiles) else {},
        }

    def upload_url(self, label: str, url: str, fpath: str, count: int):
        self.info(f'  {count}x{label}: ')
        props = {
            'single': self.upload_single(url=url, fpath=fpath, count=10),
        }
        if count > 1:
            props['serial'] = self.upload_serial(url=url, fpath=fpath, count=count)
            props['parallel'] = self.upload_parallel(url=url, fpath=fpath, count=count)
        self.info('ok.\n')
        return props

    def uploads(self, count: int, fsizes: List[int]) -> Dict[str, Any]:
        scores = {}
        url = f'https://{self.env.domain2}:{self.server_port}/curltest/put'
        fpaths = {}
        for fsize in fsizes:
            label = self.fmt_size(fsize)
            fname = f'upload{label}.data'
            fpaths[label] = self._make_docs_file(docs_dir=self.env.gen_dir,
                                                 fname=fname, fsize=fsize)

        for label, fpath in fpaths.items():
            scores[label] = self.upload_url(label=label, url=url, fpath=fpath,
                                            count=count)
        return scores

    def do_requests(self, url: str, count: int, max_parallel: int = 1):
        sample_size = 1
        samples = []
        errors = []
        profiles = []
        url = f'{url}?[0-{count - 1}]'
        extra_args = [
            '-w', '%{response_code},\\n',
        ]
        if max_parallel > 1:
            extra_args.extend([
               '--parallel', '--parallel-max', str(max_parallel)
            ])
        self.info(f'{max_parallel}...')
        for _ in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl,
                              server_addr=self.server_addr)
            r = curl.http_download(urls=[url], alpn_proto=self.protocol, no_save=True,
                                   with_headers=False, with_profile=True,
                                   with_stats=False, extra_args=extra_args)
            if r.exit_code != 0:
                errors.append(f'exit={r.exit_code}')
            else:
                samples.append(count / r.duration.total_seconds())
                non_200s = 0
                for line in r.stdout.splitlines():
                    if not line.startswith('200,'):
                        non_200s += 1
                if non_200s > 0:
                    errors.append(f'responses != 200: {non_200s}')
            profiles.append(r.profile)
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors,
            'stats': RunProfile.AverageStats(profiles),
        }

    def requests_url(self, url: str, count: int):
        self.info(f'  {url}: ')
        props = {}
        # 300 is max in curl, see tool_main.h
        for m in [1, 6, 25, 50, 100, 300]:
            props[str(m)] = self.do_requests(url=url, count=count, max_parallel=m)
        self.info('ok.\n')
        return props

    def requests(self, req_count) -> Dict[str, Any]:
        url = f'https://{self.env.domain1}:{self.server_port}/reqs10.data'
        return {
            'count': req_count,
            '10KB': self.requests_url(url=url, count=req_count),
        }

    def score(self,
              handshakes: bool = True,
              downloads: Optional[List[int]] = None,
              download_count: int = 50,
              uploads: Optional[List[int]] = None,
              upload_count: int = 50,
              req_count=5000,
              requests: bool = True):
        self.info(f"scoring {self.protocol} against {self.server_descr}\n")
        p = {}
        if self.protocol == 'h3':
            p['name'] = 'h3'
            if not self.env.have_h3_curl():
                raise ScoreCardError('curl does not support HTTP/3')
            for lib in ['ngtcp2', 'quiche', 'msh3', 'nghttp3']:
                if self.env.curl_uses_lib(lib):
                    p['implementation'] = lib
                    break
        elif self.protocol == 'h2':
            p['name'] = 'h2'
            if not self.env.have_h2_curl():
                raise ScoreCardError('curl does not support HTTP/2')
            for lib in ['nghttp2']:
                if self.env.curl_uses_lib(lib):
                    p['implementation'] = lib
                    break
        elif self.protocol == 'h1' or self.protocol == 'http/1.1':
            proto = 'http/1.1'
            p['name'] = proto
            p['implementation'] = 'native'
        else:
            raise ScoreCardError(f"unknown protocol: {self.protocol}")

        if 'implementation' not in p:
            raise ScoreCardError(f'did not recognized {p} lib')
        p['version'] = Env.curl_lib_version(p['implementation'])

        score = {
            'curl': self.env.curl_fullname(),
            'os': self.env.curl_os(),
            'protocol': p,
            'server': self.server_descr,
        }
        if handshakes:
            score['handshakes'] = self.handshakes()
        if downloads and len(downloads) > 0:
            score['downloads'] = self.downloads(count=download_count,
                                                fsizes=downloads)
        if uploads and len(uploads) > 0:
            score['uploads'] = self.uploads(count=upload_count,
                                            fsizes=uploads)
        if requests:
            score['requests'] = self.requests(req_count=req_count)
        self.info("\n")
        return score

    def fmt_ms(self, tval):
        return f'{int(tval*1000)} ms' if tval >= 0 else '--'

    def fmt_size(self, val):
        if val >= (1024*1024*1024):
            return f'{val / (1024*1024*1024):0.000f}GB'
        elif val >= (1024 * 1024):
            return f'{val / (1024*1024):0.000f}MB'
        elif val >= 1024:
            return f'{val / 1024:0.000f}KB'
        else:
            return f'{val:0.000f}B'

    def fmt_mbs(self, val):
        return f'{val/(1024*1024):0.000f} MB/s' if val >= 0 else '--'

    def fmt_reqs(self, val):
        return f'{val:0.000f} r/s' if val >= 0 else '--'

    def print_score(self, score):
        print(f'{score["protocol"]["name"].upper()} in {score["curl"]}')
        if 'handshakes' in score:
            print(f'{"Handshakes":<24} {"ipv4":25} {"ipv6":28}')
            print(f'  {"Host":<17} {"Connect":>12} {"Handshake":>12} '
                  f'{"Connect":>12} {"Handshake":>12}     {"Errors":<20}')
            for key, val in score["handshakes"].items():
                print(f'  {key:<17} {self.fmt_ms(val["ipv4-connect"]):>12} '
                      f'{self.fmt_ms(val["ipv4-handshake"]):>12} '
                      f'{self.fmt_ms(val["ipv6-connect"]):>12} '
                      f'{self.fmt_ms(val["ipv6-handshake"]):>12}     '
                      f'{"/".join(val["ipv4-errors"] + val["ipv6-errors"]):<20}'
                      )
        if 'downloads' in score:
            # get the key names of all sizes and measurements made
            sizes = []
            measures = []
            m_names = {}
            mcol_width = 12
            mcol_sw = 17
            for sskey, ssval in score['downloads'].items():
                if isinstance(ssval, str):
                    continue
                if sskey not in sizes:
                    sizes.append(sskey)
                for mkey, mval in score['downloads'][sskey].items():
                    if mkey not in measures:
                        measures.append(mkey)
                        m_names[mkey] = f'{mkey}({mval["count"]}x{mval["max-parallel"]})'
            print(f'Downloads from {score["server"]}')
            print(f'  {"Size":>8}', end='')
            for m in measures:
                print(f' {m_names[m]:>{mcol_width}} {"[cpu/rss]":<{mcol_sw}}', end='')
            print(f' {"Errors":^20}')

            for size in score['downloads']:
                size_score = score['downloads'][size]
                print(f'  {size:>8}', end='')
                errors = []
                for val in size_score.values():
                    if 'errors' in val:
                        errors.extend(val['errors'])
                for m in measures:
                    if m in size_score:
                        print(f' {self.fmt_mbs(size_score[m]["speed"]):>{mcol_width}}', end='')
                        s = f'[{size_score[m]["stats"]["cpu"]:>.1f}%'\
                            f'/{self.fmt_size(size_score[m]["stats"]["rss"])}]'
                        print(f' {s:<{mcol_sw}}', end='')
                    else:
                        print(' '*mcol_width, end='')
                if len(errors):
                    print(f' {"/".join(errors):<20}')
                else:
                    print(f' {"-":^20}')

        if 'uploads' in score:
            # get the key names of all sizes and measurements made
            sizes = []
            measures = []
            m_names = {}
            mcol_width = 12
            mcol_sw = 17
            for sskey, ssval in score['uploads'].items():
                if isinstance(ssval, str):
                    continue
                if sskey not in sizes:
                    sizes.append(sskey)
                for mkey, mval in ssval.items():
                    if mkey not in measures:
                        measures.append(mkey)
                        m_names[mkey] = f'{mkey}({mval["count"]}x{mval["max-parallel"]})'

            print(f'Uploads to {score["server"]}')
            print(f'  {"Size":>8}', end='')
            for m in measures:
                print(f' {m_names[m]:>{mcol_width}} {"[cpu/rss]":<{mcol_sw}}', end='')
            print(f' {"Errors":^20}')

            for size in sizes:
                size_score = score['uploads'][size]
                print(f'  {size:>8}', end='')
                errors = []
                for val in size_score.values():
                    if 'errors' in val:
                        errors.extend(val['errors'])
                for m in measures:
                    if m in size_score:
                        print(f' {self.fmt_mbs(size_score[m]["speed"]):>{mcol_width}}', end='')
                        stats = size_score[m]["stats"]
                        if 'cpu' in stats:
                            s = f'[{stats["cpu"]:>.1f}%/{self.fmt_size(stats["rss"])}]'
                        else:
                            s = '[???/???]'
                        print(f' {s:<{mcol_sw}}', end='')
                    else:
                        print(' '*mcol_width, end='')
                if len(errors):
                    print(f' {"/".join(errors):<20}')
                else:
                    print(f' {"-":^20}')

        if 'requests' in score:
            sizes = []
            measures = []
            m_names = {}
            mcol_width = 9
            mcol_sw = 13
            for sskey, ssval in score['requests'].items():
                if isinstance(ssval, (str, int)):
                    continue
                if sskey not in sizes:
                    sizes.append(sskey)
                for mkey in score['requests'][sskey]:
                    if mkey not in measures:
                        measures.append(mkey)
                        m_names[mkey] = f'{mkey}'

            print('Requests (max parallel) to {score["server"]}')
            print(f'  {"Size":>6} {"Reqs":>6}', end='')
            for m in measures:
                print(f' {m_names[m]:>{mcol_width}} {"[cpu/rss]":<{mcol_sw}}', end='')
            print(f' {"Errors":^10}')

            for size in sizes:
                size_score = score['requests'][size]
                count = score['requests']['count']
                print(f'  {size:>6} {count:>6}', end='')
                errors = []
                for val in size_score.values():
                    if 'errors' in val:
                        errors.extend(val['errors'])
                for m in measures:
                    if m in size_score:
                        print(f' {self.fmt_reqs(size_score[m]["speed"]):>{mcol_width}}', end='')
                        s = f'[{size_score[m]["stats"]["cpu"]:>.1f}%'\
                            f'/{self.fmt_size(size_score[m]["stats"]["rss"])}]'
                        print(f' {s:<{mcol_sw}}', end='')
                    else:
                        print(' '*mcol_width, end='')
                if len(errors):
                    print(f' {"/".join(errors):<10}')
                else:
                    print(f' {"-":^10}')


def parse_size(s):
    m = re.match(r'(\d+)(mb|kb|gb)?', s, re.IGNORECASE)
    if m is None:
        raise Exception(f'unrecognized size: {s}')
    size = int(m.group(1))
    if not m.group(2):
        pass
    elif m.group(2).lower() == 'kb':
        size *= 1024
    elif m.group(2).lower() == 'mb':
        size *= 1024 * 1024
    elif m.group(2).lower() == 'gb':
        size *= 1024 * 1024 * 1024
    return size


def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a range of tests to give a scorecard for a HTTP protocol
        'h3' or 'h2' implementation in curl.
        """)
    parser.add_argument("-v", "--verbose", action='count', default=1,
                        help="log more output on stderr")
    parser.add_argument("-j", "--json", action='store_true',
                        default=False, help="print json instead of text")
    parser.add_argument("-H", "--handshakes", action='store_true',
                        default=False, help="evaluate handshakes only")
    parser.add_argument("-d", "--downloads", action='store_true',
                        default=False, help="evaluate downloads")
    parser.add_argument("--download", action='append', type=str,
                        default=None, help="evaluate download size")
    parser.add_argument("--download-count", action='store', type=int,
                        default=50, help="perform that many downloads")
    parser.add_argument("--download-parallel", action='store', type=int,
                        default=0, help="perform that many downloads in parallel (default all)")
    parser.add_argument("-u", "--uploads", action='store_true',
                        default=False, help="evaluate uploads")
    parser.add_argument("--upload", action='append', type=str,
                        default=None, help="evaluate upload size")
    parser.add_argument("--upload-count", action='store', type=int,
                        default=50, help="perform that many uploads")
    parser.add_argument("-r", "--requests", action='store_true',
                        default=False, help="evaluate requests")
    parser.add_argument("--request-count", action='store', type=int,
                        default=5000, help="perform that many requests")
    parser.add_argument("--httpd", action='store_true', default=False,
                        help="evaluate httpd server only")
    parser.add_argument("--caddy", action='store_true', default=False,
                        help="evaluate caddy server only")
    parser.add_argument("--curl-verbose", action='store_true',
                        default=False, help="run curl with `-v`")
    parser.add_argument("protocol", default='h2', nargs='?',
                        help="Name of protocol to score")
    parser.add_argument("--start-only", action='store_true', default=False,
                        help="only start the servers")
    parser.add_argument("--remote", action='store', type=str,
                        default=None, help="score against the remote server at <ip>:<port>")
    args = parser.parse_args()

    if args.verbose > 0:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logging.getLogger('').addHandler(console)

    protocol = args.protocol
    handshakes = True
    downloads = [1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024]
    if args.download is not None:
        downloads = []
        for x in args.download:
            downloads.extend([parse_size(s) for s in x.split(',')])

    uploads = [1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024]
    if args.upload is not None:
        uploads = []
        for x in args.upload:
            uploads.extend([parse_size(s) for s in x.split(',')])

    requests = True
    if args.downloads or args.uploads or args.requests or args.handshakes:
        handshakes = args.handshakes
        if not args.downloads:
            downloads = None
        if not args.uploads:
            uploads = None
        requests = args.requests

    test_httpd = protocol != 'h3'
    test_caddy = True
    if args.caddy or args.httpd:
        test_caddy = args.caddy
        test_httpd = args.httpd

    rv = 0
    env = Env()
    env.setup()
    env.test_timeout = None
    httpd = None
    nghttpx = None
    caddy = None
    try:
        cards = []

        if args.remote:
            m = re.match(r'^(.+):(\d+)$', args.remote)
            if m is None:
                raise ScoreCardError(f'unable to parse ip:port from --remote {args.remote}')
            test_httpd = False
            test_caddy = False
            remote_addr = m.group(1)
            remote_port = int(m.group(2))
            card = ScoreCard(env=env,
                             protocol=protocol,
                             server_descr=f'Server at {args.remote}',
                             server_addr=remote_addr,
                             server_port=remote_port,
                             verbose=args.verbose, curl_verbose=args.curl_verbose,
                             download_parallel=args.download_parallel)
            cards.append(card)

        if test_httpd:
            httpd = Httpd(env=env)
            assert httpd.exists(), \
                f'httpd not found: {env.httpd}'
            httpd.clear_logs()
            server_docs = httpd.docs_dir
            assert httpd.start()
            if protocol == 'h3':
                nghttpx = NghttpxQuic(env=env)
                nghttpx.clear_logs()
                assert nghttpx.start()
                server_descr = f'nghttpx: https:{env.h3_port} [backend httpd: {env.httpd_version()}, https:{env.https_port}]'
                server_port = env.h3_port
            else:
                server_descr = f'httpd: {env.httpd_version()}, http:{env.http_port} https:{env.https_port}'
                server_port = env.https_port
            card = ScoreCard(env=env,
                             protocol=protocol,
                             server_descr=server_descr,
                             server_port=server_port,
                             verbose=args.verbose, curl_verbose=args.curl_verbose,
                             download_parallel=args.download_parallel)
            card.setup_resources(server_docs, downloads)
            cards.append(card)

        if test_caddy and env.caddy:
            backend = ''
            if uploads and httpd is None:
                backend = f' [backend httpd: {env.httpd_version()}, http:{env.http_port} https:{env.https_port}]'
                httpd = Httpd(env=env)
                assert httpd.exists(), \
                    f'httpd not found: {env.httpd}'
                httpd.clear_logs()
                assert httpd.start()
            caddy = Caddy(env=env)
            caddy.clear_logs()
            assert caddy.start()
            server_descr = f'Caddy: {env.caddy_version()}, http:{env.caddy_http_port} https:{env.caddy_https_port}{backend}'
            server_port = caddy.port
            server_docs = caddy.docs_dir
            card = ScoreCard(env=env,
                             protocol=protocol,
                             server_descr=server_descr,
                             server_port=server_port,
                             verbose=args.verbose, curl_verbose=args.curl_verbose,
                             download_parallel=args.download_parallel)
            card.setup_resources(server_docs, downloads)
            cards.append(card)

        if args.start_only:
            print('started servers:')
            for card in cards:
                print(f'{card.server_descr}')
            sys.stderr.write('press [RETURN] to finish')
            sys.stderr.flush()
            sys.stdin.readline()
        else:
            for card in cards:
                score = card.score(handshakes=handshakes,
                                   downloads=downloads,
                                   download_count=args.download_count,
                                   uploads=uploads,
                                   upload_count=args.upload_count,
                                   req_count=args.request_count,
                                   requests=requests)
                if args.json:
                    print(json.JSONEncoder(indent=2).encode(score))
                else:
                    card.print_score(score)

    except ScoreCardError as ex:
        sys.stderr.write(f"ERROR: {ex}\n")
        rv = 1
    except KeyboardInterrupt:
        log.warning("aborted")
        rv = 1
    finally:
        if caddy:
            caddy.stop()
        if nghttpx:
            nghttpx.stop(wait_dead=False)
        if httpd:
            httpd.stop()
    sys.exit(rv)


if __name__ == "__main__":
    main()
