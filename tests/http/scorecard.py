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
import datetime
import json
import logging
import os
import re
import sys
from statistics import mean
from typing import Dict, Any, Optional, List

from testenv import Env, Httpd, CurlClient, Caddy, ExecResult, NghttpxQuic, RunProfile, Dante

log = logging.getLogger(__name__)


class ScoreCardError(Exception):
    pass


class Card:
    @classmethod
    def fmt_ms(cls, tval):
        return f'{int(tval*1000)} ms' if tval >= 0 else '--'

    @classmethod
    def fmt_size(cls, val):
        if val >= (1024*1024*1024):
            return f'{val / (1024*1024*1024):0.000f}GB'
        elif val >= (1024 * 1024):
            return f'{val / (1024*1024):0.000f}MB'
        elif val >= 1024:
            return f'{val / 1024:0.000f}KB'
        else:
            return f'{val:0.000f}B'

    @classmethod
    def fmt_mbs(cls, val):
        if val is None or val < 0:
            return '--'
        if val >= (1024*1024):
            return f'{val/(1024*1024):0.000f} MB/s'
        elif val >= 1024:
            return f'{val / 1024:0.000f} KB/s'
        else:
            return f'{val:0.000f} B/s'

    @classmethod
    def fmt_reqs(cls, val):
        return f'{val:0.000f} r/s' if val >= 0 else '--'

    @classmethod
    def mk_mbs_cell(cls, samples, profiles, errors):
        val = mean(samples) if len(samples) else -1
        cell = {
            'val': val,
            'sval': Card.fmt_mbs(val) if val >= 0 else '--',
        }
        if len(profiles):
            cell['stats'] = RunProfile.AverageStats(profiles)
        if len(errors):
            cell['errors'] = errors
        return cell

    @classmethod
    def mk_reqs_cell(cls, samples, profiles, errors):
        val = mean(samples) if len(samples) else -1
        cell = {
            'val': val,
            'sval': Card.fmt_reqs(val) if val >= 0 else '--',
        }
        if len(profiles):
            cell['stats'] = RunProfile.AverageStats(profiles)
        if len(errors):
            cell['errors'] = errors
        return cell

    @classmethod
    def parse_size(cls, s):
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

    @classmethod
    def print_score(cls, score):
        print(f'Scorecard curl, protocol {score["meta"]["protocol"]} '
              f'via {score["meta"]["implementation"]}/'
              f'{score["meta"]["implementation_version"]}')
        print(f'Date: {score["meta"]["date"]}')
        if 'curl_V' in score["meta"]:
            print(f'Version: {score["meta"]["curl_V"]}')
        if 'curl_features' in score["meta"]:
            print(f'Features: {score["meta"]["curl_features"]}')
        if 'limit-rate' in score['meta']:
            print(f'--limit-rate: {score["meta"]["limit-rate"]}')
        print(f'Samples Size: {score["meta"]["samples"]}')
        if 'handshakes' in score:
            print(f'{"Handshakes":<24} {"ipv4":25} {"ipv6":28}')
            print(f'  {"Host":<17} {"Connect":>12} {"Handshake":>12} '
                  f'{"Connect":>12} {"Handshake":>12}     {"Errors":<20}')
            for key, val in score["handshakes"].items():
                print(f'  {key:<17} {Card.fmt_ms(val["ipv4-connect"]):>12} '
                      f'{Card.fmt_ms(val["ipv4-handshake"]):>12} '
                      f'{Card.fmt_ms(val["ipv6-connect"]):>12} '
                      f'{Card.fmt_ms(val["ipv6-handshake"]):>12}     '
                      f'{"/".join(val["ipv4-errors"] + val["ipv6-errors"]):<20}'
                      )
        for name in ['downloads', 'uploads', 'requests']:
            if name in score:
                Card.print_score_table(score[name])

    @classmethod
    def print_score_table(cls, score):
        cols = score['cols']
        rows = score['rows']
        colw = []
        statw = 13
        errors = []
        col_has_stats = []
        for idx, col in enumerate(cols):
            cellw = max([len(r[idx]["sval"]) for r in rows])
            colw.append(max(cellw, len(col)))
            col_has_stats.append(False)
            for row in rows:
                if 'stats' in row[idx]:
                    col_has_stats[idx] = True
                    break
        if 'title' in score['meta']:
            print(score['meta']['title'])
        for idx, col in enumerate(cols):
            if col_has_stats[idx]:
                print(f'  {col:>{colw[idx]}} {"[cpu/rss]":<{statw}}', end='')
            else:
                print(f'  {col:>{colw[idx]}}', end='')
        print('')
        for row in rows:
            for idx, cell in enumerate(row):
                print(f'  {cell["sval"]:>{colw[idx]}}', end='')
                if col_has_stats[idx]:
                    if 'stats' in cell:
                        s = f'[{cell["stats"]["cpu"]:>.1f}%' \
                            f'/{Card.fmt_size(cell["stats"]["rss"])}]'
                    else:
                        s = ''
                    print(f' {s:<{statw}}', end='')
                if 'errors' in cell:
                    errors.extend(cell['errors'])
            print('')
        if len(errors):
            print(f'Errors: {errors}')


class ScoreRunner:

    def __init__(self, env: Env,
                 protocol: str,
                 server_descr: str,
                 server_port: int,
                 verbose: int,
                 curl_verbose: int,
                 download_parallel: int = 0,
                 server_addr: Optional[str] = None,
                 with_dtrace: bool = False,
                 with_flame: bool = False,
                 socks_args: Optional[List[str]] = None,
                 limit_rate: Optional[str] = None):
        self.verbose = verbose
        self.env = env
        self.protocol = protocol
        self.server_descr = server_descr
        self.server_addr = server_addr
        self.server_port = server_port
        self._silent_curl = not curl_verbose
        self._download_parallel = download_parallel
        self._with_dtrace = with_dtrace
        self._with_flame = with_flame
        self._socks_args = socks_args
        self._limit_rate = limit_rate

    def info(self, msg):
        if self.verbose > 0:
            sys.stderr.write(msg)
            sys.stderr.flush()

    def mk_curl_client(self):
        return CurlClient(env=self.env, silent=self._silent_curl,
                          server_addr=self.server_addr,
                          with_dtrace=self._with_dtrace,
                          with_flame=self._with_flame,
                          socks_args=self._socks_args)

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
                    curl = self.mk_curl_client()
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
        if downloads is not None:
            for fsize in downloads:
                label = Card.fmt_size(fsize)
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

    def dl_single(self, url: str, nsamples: int = 1):
        count = 1
        samples = []
        errors = []
        profiles = []
        self.info('single...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True, with_headers=False,
                                   with_profile=True,
                                   limit_rate=self._limit_rate)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return Card.mk_mbs_cell(samples, profiles, errors)

    def dl_serial(self, url: str, count: int, nsamples: int = 1):
        samples = []
        errors = []
        profiles = []
        url = f'{url}?[0-{count - 1}]'
        self.info('serial...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True,
                                   with_headers=False,
                                   with_profile=True,
                                   limit_rate=self._limit_rate)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return Card.mk_mbs_cell(samples, profiles, errors)

    def dl_parallel(self, url: str, count: int, nsamples: int = 1):
        samples = []
        errors = []
        profiles = []
        max_parallel = self._download_parallel if self._download_parallel > 0 else count
        url = f'{url}?[0-{count - 1}]'
        self.info('parallel...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
            r = curl.http_download(urls=[url], alpn_proto=self.protocol,
                                   no_save=True,
                                   with_headers=False,
                                   with_profile=True,
                                   limit_rate=self._limit_rate,
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
        return Card.mk_mbs_cell(samples, profiles, errors)

    def downloads(self, count: int, fsizes: List[int], meta: Dict[str, Any]) -> Dict[str, Any]:
        nsamples = meta['samples']
        max_parallel = self._download_parallel if self._download_parallel > 0 else count
        cols = ['size']
        if not self._download_parallel:
            cols.append('single')
            if count > 1:
                cols.append(f'serial({count})')
        if count > 1:
            cols.append(f'parallel({count}x{max_parallel})')
        rows = []
        for fsize in fsizes:
            row = [{
                'val': fsize,
                'sval': Card.fmt_size(fsize)
            }]
            self.info(f'{row[0]["sval"]} downloads...')
            url = f'https://{self.env.domain1}:{self.server_port}/score{row[0]["sval"]}.data'
            if 'single' in cols:
                row.append(self.dl_single(url=url, nsamples=nsamples))
            if count > 1:
                if 'single' in cols:
                    row.append(self.dl_serial(url=url, count=count, nsamples=nsamples))
                row.append(self.dl_parallel(url=url, count=count, nsamples=nsamples))
            rows.append(row)
            self.info('done.\n')
        title = f'Downloads from {meta["server"]}'
        if self._socks_args:
            title += f' via {self._socks_args}'
        return {
            'meta': {
                'title': title,
                'count': count,
                'max-parallel': max_parallel,
            },
            'cols': cols,
            'rows': rows,
        }

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

    def ul_single(self, url: str, fpath: str, nsamples: int = 1):
        samples = []
        errors = []
        profiles = []
        self.info('single...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
            r = curl.http_put(urls=[url], fdata=fpath, alpn_proto=self.protocol,
                              with_headers=False, with_profile=True)
            err = self._check_uploads(r, 1)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_upload'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return Card.mk_mbs_cell(samples, profiles, errors)

    def ul_serial(self, url: str, fpath: str, count: int, nsamples: int = 1):
        samples = []
        errors = []
        profiles = []
        url = f'{url}?id=[0-{count - 1}]'
        self.info('serial...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
            r = curl.http_put(urls=[url], fdata=fpath, alpn_proto=self.protocol,
                              with_headers=False, with_profile=True)
            err = self._check_uploads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_upload'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
                profiles.append(r.profile)
        return Card.mk_mbs_cell(samples, profiles, errors)

    def ul_parallel(self, url: str, fpath: str, count: int, nsamples: int = 1):
        samples = []
        errors = []
        profiles = []
        max_parallel = self._download_parallel if self._download_parallel > 0 else count
        url = f'{url}?id=[0-{count - 1}]'
        self.info('parallel...')
        for _ in range(nsamples):
            curl = self.mk_curl_client()
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
        return Card.mk_mbs_cell(samples, profiles, errors)

    def uploads(self, count: int, fsizes: List[int], meta: Dict[str, Any]) -> Dict[str, Any]:
        nsamples = meta['samples']
        max_parallel = self._download_parallel if self._download_parallel > 0 else count
        url = f'https://{self.env.domain2}:{self.server_port}/curltest/put'
        cols = ['size', 'single']
        if count > 1:
            cols.append(f'serial({count})')
            cols.append(f'parallel({count}x{max_parallel})')
        rows = []
        for fsize in fsizes:
            row = [{
                'val': fsize,
                'sval': Card.fmt_size(fsize)
            }]
            fname = f'upload{row[0]["sval"]}.data'
            fpath = self._make_docs_file(docs_dir=self.env.gen_dir,
                                         fname=fname, fsize=fsize)

            self.info(f'{row[0]["sval"]} uploads...')
            row.append(self.ul_single(url=url, fpath=fpath, nsamples=nsamples))
            if count > 1:
                row.append(self.ul_serial(url=url, fpath=fpath, count=count, nsamples=nsamples))
                row.append(self.ul_parallel(url=url, fpath=fpath, count=count, nsamples=nsamples))
            rows.append(row)
            self.info('done.\n')
        title = f'Uploads to {meta["server"]}'
        if self._socks_args:
            title += f' via {self._socks_args}'
        return {
            'meta': {
                'title': title,
                'count': count,
                'max-parallel': max_parallel,
            },
            'cols': cols,
            'rows': rows,
        }

    def do_requests(self, url: str, count: int, max_parallel: int = 1, nsamples: int = 1):
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
        for _ in range(nsamples):
            curl = self.mk_curl_client()
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
        return Card.mk_reqs_cell(samples, profiles, errors)

    def requests(self, count: int, meta: Dict[str, Any]) -> Dict[str, Any]:
        url = f'https://{self.env.domain1}:{self.server_port}/reqs10.data'
        fsize = 10*1024
        cols = ['size', 'total']
        rows = []
        mparallel = meta['request_parallels']
        cols.extend([f'{mp} max' for mp in mparallel])
        row = [{
            'val': fsize,
            'sval': Card.fmt_size(fsize)
        },{
            'val': count,
            'sval': f'{count}',
        }]
        self.info('requests, max parallel...')
        row.extend([self.do_requests(url=url, count=count,
                                     max_parallel=mp, nsamples=meta["samples"])
                    for mp in mparallel])
        rows.append(row)
        self.info('done.\n')
        title = f'Requests in parallel to {meta["server"]}'
        if self._socks_args:
            title += f' via {self._socks_args}'
        return {
            'meta': {
                'title': title,
                'count': count,
            },
            'cols': cols,
            'rows': rows,
        }

    def score(self,
              handshakes: bool = True,
              downloads: Optional[List[int]] = None,
              download_count: int = 50,
              uploads: Optional[List[int]] = None,
              upload_count: int = 50,
              req_count=5000,
              request_parallels=None,
              nsamples: int = 1,
              requests: bool = True):
        self.info(f"scoring {self.protocol} against {self.server_descr}\n")

        score = {
            'meta': {
                'curl_version': self.env.curl_version(),
                'curl_V': self.env.curl_fullname(),
                'curl_features': self.env.curl_features_string(),
                'os': self.env.curl_os(),
                'server': self.server_descr,
                'samples': nsamples,
                'date': f'{datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}',
            }
        }
        if self._limit_rate:
            score['meta']['limit-rate'] = self._limit_rate

        if self.protocol == 'h3':
            score['meta']['protocol'] = 'h3'
            if not self.env.have_h3_curl():
                raise ScoreCardError('curl does not support HTTP/3')
            for lib in ['ngtcp2', 'quiche', 'nghttp3']:
                if self.env.curl_uses_lib(lib):
                    score['meta']['implementation'] = lib
                    break
        elif self.protocol == 'h2':
            score['meta']['protocol'] = 'h2'
            if not self.env.have_h2_curl():
                raise ScoreCardError('curl does not support HTTP/2')
            for lib in ['nghttp2']:
                if self.env.curl_uses_lib(lib):
                    score['meta']['implementation'] = lib
                    break
        elif self.protocol == 'h1' or self.protocol == 'http/1.1':
            score['meta']['protocol'] = 'http/1.1'
            score['meta']['implementation'] = 'native'
        else:
            raise ScoreCardError(f"unknown protocol: {self.protocol}")

        if 'implementation' not in score['meta']:
            raise ScoreCardError('did not recognized protocol lib')
        score['meta']['implementation_version'] = Env.curl_lib_version(score['meta']['implementation'])

        if handshakes:
            score['handshakes'] = self.handshakes()
        if downloads and len(downloads) > 0:
            score['downloads'] = self.downloads(count=download_count,
                                                fsizes=downloads,
                                                meta=score['meta'])
        if uploads and len(uploads) > 0:
            score['uploads'] = self.uploads(count=upload_count,
                                            fsizes=uploads,
                                            meta=score['meta'])
        if requests:
            if request_parallels is None:
                request_parallels = [1, 6, 25, 50, 100, 300]
            score['meta']['request_parallels'] = request_parallels
            score['requests'] = self.requests(count=req_count, meta=score['meta'])
        return score


def run_score(args, protocol):
    if protocol not in ['http/1.1', 'h1', 'h2', 'h3']:
        sys.stderr.write(f'ERROR: protocol "{protocol}" not known to scorecard\n')
        sys.exit(1)
    if protocol == 'h1':
        protocol = 'http/1.1'

    handshakes = True
    downloads = [1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024]
    if args.download_sizes is not None:
        downloads = []
        for x in args.download_sizes:
            downloads.extend([Card.parse_size(s) for s in x.split(',')])

    uploads = [1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024]
    if args.upload_sizes is not None:
        uploads = []
        for x in args.upload_sizes:
            uploads.extend([Card.parse_size(s) for s in x.split(',')])

    requests = True
    request_parallels = None
    if args.request_parallels:
        request_parallels = []
        for x in args.request_parallels:
            request_parallels.extend([int(s) for s in x.split(',')])


    if args.downloads or args.uploads or args.requests or args.handshakes:
        handshakes = args.handshakes
        if not args.downloads:
            downloads = None
        if not args.uploads:
            uploads = None
        requests = args.requests

    test_httpd = protocol != 'h3'
    test_caddy = protocol == 'h3'
    if args.caddy or args.httpd:
        test_caddy = args.caddy
        test_httpd = args.httpd

    rv = 0
    env = Env()
    env.setup()
    env.test_timeout = None

    sockd = None
    socks_args = None
    if args.socks4 and args.socks5:
        raise ScoreCardError('unable to run --socks4 and --socks5 together')
    elif args.socks4 or args.socks5:
        sockd = Dante(env=env)
    if sockd:
        assert sockd.initial_start()
        socks_args = [
            '--socks4' if args.socks4 else '--socks5',
            f'127.0.0.1:{sockd.port}',
        ]

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
            card = ScoreRunner(env=env,
                               protocol=protocol,
                               server_descr=f'Server at {args.remote}',
                               server_addr=remote_addr,
                               server_port=remote_port,
                               verbose=args.verbose,
                               curl_verbose=args.curl_verbose,
                               download_parallel=args.download_parallel,
                               with_dtrace=args.dtrace,
                               with_flame=args.flame,
                               socks_args=socks_args,
                               limit_rate=args.limit_rate)
            cards.append(card)

        if test_httpd:
            httpd = Httpd(env=env)
            assert httpd.exists(), \
                f'httpd not found: {env.httpd}'
            httpd.clear_logs()
            server_docs = httpd.docs_dir
            assert httpd.initial_start()
            if protocol == 'h3':
                nghttpx = NghttpxQuic(env=env)
                nghttpx.clear_logs()
                assert nghttpx.initial_start()
                server_descr = f'nghttpx: https:{env.h3_port} [backend httpd/{env.httpd_version()}]'
                server_port = env.h3_port
            else:
                server_descr = f'httpd/{env.httpd_version()}'
                server_port = env.https_port
            card = ScoreRunner(env=env,
                               protocol=protocol,
                               server_descr=server_descr,
                               server_port=server_port,
                               verbose=args.verbose, curl_verbose=args.curl_verbose,
                               download_parallel=args.download_parallel,
                               with_dtrace=args.dtrace,
                               with_flame=args.flame,
                               socks_args=socks_args,
                               limit_rate=args.limit_rate)
            card.setup_resources(server_docs, downloads)
            cards.append(card)

        if test_caddy and env.caddy:
            backend = ''
            if uploads and httpd is None:
                backend = f' [backend httpd: {env.httpd_version()}]'
                httpd = Httpd(env=env)
                assert httpd.exists(), \
                    f'httpd not found: {env.httpd}'
                httpd.clear_logs()
                assert httpd.initial_start()
            caddy = Caddy(env=env)
            caddy.clear_logs()
            assert caddy.initial_start()
            server_descr = f'Caddy/{env.caddy_version()} {backend}'
            server_port = caddy.port
            server_docs = caddy.docs_dir
            card = ScoreRunner(env=env,
                               protocol=protocol,
                               server_descr=server_descr,
                               server_port=server_port,
                               verbose=args.verbose, curl_verbose=args.curl_verbose,
                               download_parallel=args.download_parallel,
                               with_dtrace=args.dtrace,
                               socks_args=socks_args,
                               limit_rate=args.limit_rate)
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
                                   requests=requests,
                                   request_parallels=request_parallels,
                                   nsamples=args.samples)
                if args.json:
                    print(json.JSONEncoder(indent=2).encode(score))
                else:
                    Card.print_score(score)

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
        if sockd:
            sockd.stop()
    return rv


def print_file(filename):
    if not os.path.exists(filename):
        sys.stderr.write(f"ERROR: file does not exist {filename}\n")
        return 1
    with open(filename) as file:
        data = json.load(file)
    Card.print_score(data)
    return 0


def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a range of tests to give a scorecard for a HTTP protocol
        'h3' or 'h2' implementation in curl.
        """)
    parser.add_argument("-v", "--verbose", action='count', default=1,
                        help="log more output on stderr")
    parser.add_argument("-j", "--json", action='store_true',
                        default=False, help="print json instead of text")
    parser.add_argument("--samples", action='store', type=int, metavar='number',
                        default=1, help="how many sample runs to make")
    parser.add_argument("--httpd", action='store_true', default=False,
                        help="evaluate httpd server only")
    parser.add_argument("--caddy", action='store_true', default=False,
                        help="evaluate caddy server only")
    parser.add_argument("--curl-verbose", action='store_true',
                        default=False, help="run curl with `-v`")
    parser.add_argument("--print", type=str, default=None, metavar='filename',
                        help="print the results from a JSON file")
    parser.add_argument("protocol", default=None, nargs='?',
                        help="Name of protocol to score")
    parser.add_argument("--start-only", action='store_true', default=False,
                        help="only start the servers")
    parser.add_argument("--remote", action='store', type=str,
                        default=None, help="score against the remote server at <ip>:<port>")
    parser.add_argument("--dtrace", action='store_true',
                        default = False, help="produce dtrace of curl")
    parser.add_argument("--flame", action='store_true',
                        default = False, help="produce a flame graph on curl, implies --dtrace")
    parser.add_argument("--limit-rate", action='store', type=str,
                        default=None, help="use curl's --limit-rate")

    parser.add_argument("-H", "--handshakes", action='store_true',
                        default=False, help="evaluate handshakes only")

    parser.add_argument("-d", "--downloads", action='store_true',
                        default=False, help="evaluate downloads")
    parser.add_argument("--download-sizes", action='append', type=str,
                        metavar='numberlist',
                        default=None, help="evaluate download size")
    parser.add_argument("--download-count", action='store', type=int,
                        metavar='number',
                        default=50, help="perform that many downloads")
    parser.add_argument("--download-parallel", action='store', type=int,
                        metavar='number', default=0,
                        help="perform that many downloads in parallel (default all)")

    parser.add_argument("-u", "--uploads", action='store_true',
                        default=False, help="evaluate uploads")
    parser.add_argument("--upload-sizes", action='append', type=str,
                        metavar='numberlist',
                        default=None, help="evaluate upload size")
    parser.add_argument("--upload-count", action='store', type=int,
                        metavar='number', default=50,
                        help="perform that many uploads")

    parser.add_argument("-r", "--requests", action='store_true',
                        default=False, help="evaluate requests")
    parser.add_argument("--request-count", action='store', type=int,
                        metavar='number',
                        default=5000, help="perform that many requests")
    parser.add_argument("--request-parallels", action='append', type=str,
                        metavar='numberlist',
                        default=None, help="evaluate request with these max-parallel numbers")
    parser.add_argument("--socks4", action='store_true',
                        default=False, help="test with SOCKS4 proxy")
    parser.add_argument("--socks5", action='store_true',
                        default=False, help="test with SOCKS5 proxy")
    args = parser.parse_args()

    if args.verbose > 0:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logging.getLogger('').addHandler(console)

    if args.print:
        rv = print_file(args.print)
    elif not args.protocol:
        parser.print_usage()
        rv = 1
    else:
        rv = run_score(args, args.protocol)

    sys.exit(rv)


if __name__ == "__main__":
    main()
