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

from testenv import Env, Httpd, Nghttpx, CurlClient, Caddy, ExecResult

log = logging.getLogger(__name__)


class ScoreCardException(Exception):
    pass


class ScoreCard:

    def __init__(self, env: Env,
                 httpd: Optional[Httpd],
                 nghttpx: Optional[Nghttpx],
                 caddy: Optional[Caddy],
                 verbose: int,
                 curl_verbose: int):
        self.verbose = verbose
        self.env = env
        self.httpd = httpd
        self.nghttpx = nghttpx
        self.caddy = caddy
        self._silent_curl = not curl_verbose

    def info(self, msg):
        if self.verbose > 0:
            sys.stderr.write(msg)
            sys.stderr.flush()

    def handshakes(self, proto: str) -> Dict[str, Any]:
        props = {}
        sample_size = 5
        self.info(f'TLS Handshake\n')
        for authority in [
            f'{self.env.authority_for(self.env.domain1, proto)}'
        ]:
            self.info('  localhost...')
            c_samples = []
            hs_samples = []
            errors = []
            for i in range(sample_size):
                curl = CurlClient(env=self.env, silent=self._silent_curl)
                url = f'https://{authority}/'
                r = curl.http_download(urls=[url], alpn_proto=proto,
                                       no_save=True)
                if r.exit_code == 0 and len(r.stats) == 1:
                    c_samples.append(r.stats[0]['time_connect'])
                    hs_samples.append(r.stats[0]['time_appconnect'])
                else:
                    errors.append(f'exit={r.exit_code}')
            props['localhost'] = {
                'ipv4-connect': mean(c_samples),
                'ipv4-handshake': mean(hs_samples),
                'ipv4-errors': errors,
                'ipv6-connect': 0,
                'ipv6-handshake': 0,
                'ipv6-errors': [],
            }
            self.info('ok.\n')
        for authority in [
            'curl.se', 'nghttp2.org',
        ]:
            self.info(f'  {authority}...')
            props[authority] = {}
            for ipv in ['ipv4', 'ipv6']:
                self.info(f'{ipv}...')
                c_samples = []
                hs_samples = []
                errors = []
                for i in range(sample_size):
                    curl = CurlClient(env=self.env, silent=self._silent_curl)
                    args = [
                        '--http3-only' if proto == 'h3' else '--http2',
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
        return flen

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

    def transfer_single(self, url: str, proto: str, count: int):
        sample_size = count
        count = 1
        samples = []
        errors = []
        self.info(f'single...')
        for i in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl)
            r = curl.http_download(urls=[url], alpn_proto=proto, no_save=True,
                                   with_headers=False)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors
        }

    def transfer_serial(self, url: str, proto: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        url = f'{url}?[0-{count - 1}]'
        self.info(f'serial...')
        for i in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl)
            r = curl.http_download(urls=[url], alpn_proto=proto, no_save=True,
                                   with_headers=False)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors
        }

    def transfer_parallel(self, url: str, proto: str, count: int):
        sample_size = 1
        samples = []
        errors = []
        url = f'{url}?[0-{count - 1}]'
        self.info(f'parallel...')
        for i in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl)
            r = curl.http_download(urls=[url], alpn_proto=proto, no_save=True,
                                   with_headers=False,
                                   extra_args=['--parallel',
                                               '--parallel-max', str(count)])
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / r.duration.total_seconds())
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors
        }

    def download_url(self, label: str, url: str, proto: str, count: int):
        self.info(f'  {count}x{label}: ')
        props = {
            'single': self.transfer_single(url=url, proto=proto, count=10),
            'serial': self.transfer_serial(url=url, proto=proto, count=count),
            'parallel': self.transfer_parallel(url=url, proto=proto,
                                               count=count),
        }
        self.info(f'ok.\n')
        return props

    def downloads(self, proto: str, count: int,
                  fsizes: List[int]) -> Dict[str, Any]:
        scores = {}
        if self.httpd:
            if proto == 'h3':
                port = self.env.h3_port
                via = 'nghttpx'
                descr = f'port {port}, proxying httpd'
            else:
                port = self.env.https_port
                via = 'httpd'
                descr = f'port {port}'
            self.info(f'{via} downloads\n')
            scores[via] = {
                'description': descr,
            }
            for fsize in fsizes:
                label = f'{int(fsize / 1024)}KB' if fsize < 1024*1024 else \
                    f'{int(fsize / (1024 * 1024))}MB'
                fname = f'score{label}.data'
                self._make_docs_file(docs_dir=self.httpd.docs_dir,
                                     fname=fname, fsize=fsize)
                url = f'https://{self.env.domain1}:{port}/{fname}'
                results = self.download_url(label=label, url=url,
                                            proto=proto, count=count)
                scores[via][label] = results
        if self.caddy:
            port = self.caddy.port
            via = 'caddy'
            descr = f'port {port}'
            self.info('caddy downloads\n')
            scores[via] = {
                'description': descr,
            }
            for fsize in fsizes:
                label = f'{int(fsize / 1024)}KB' if fsize < 1024*1024 else \
                    f'{int(fsize / (1024 * 1024))}MB'
                fname = f'score{label}.data'
                self._make_docs_file(docs_dir=self.caddy.docs_dir,
                                     fname=fname, fsize=fsize)
                url = f'https://{self.env.domain1}:{port}/{fname}'
                results = self.download_url(label=label, url=url,
                                            proto=proto, count=count)
                scores[via][label] = results
        return scores

    def do_requests(self, url: str, proto: str, count: int,
                    max_parallel: int = 1):
        sample_size = 1
        samples = []
        errors = []
        url = f'{url}?[0-{count - 1}]'
        extra_args = ['--parallel', '--parallel-max', str(max_parallel)] \
            if max_parallel > 1 else []
        self.info(f'{max_parallel}...')
        for i in range(sample_size):
            curl = CurlClient(env=self.env, silent=self._silent_curl)
            r = curl.http_download(urls=[url], alpn_proto=proto, no_save=True,
                                   with_headers=False,
                                   extra_args=extra_args)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                for _ in r.stats:
                    samples.append(count / r.duration.total_seconds())
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors
        }

    def requests_url(self, url: str, proto: str, count: int):
        self.info(f'  {url}: ')
        props = {
            'serial': self.do_requests(url=url, proto=proto, count=count),
            'par-6': self.do_requests(url=url, proto=proto, count=count,
                                      max_parallel=6),
            'par-25': self.do_requests(url=url, proto=proto, count=count,
                                       max_parallel=25),
            'par-50': self.do_requests(url=url, proto=proto, count=count,
                                       max_parallel=50),
            'par-100': self.do_requests(url=url, proto=proto, count=count,
                                        max_parallel=100),
        }
        self.info(f'ok.\n')
        return props

    def requests(self, proto: str) -> Dict[str, Any]:
        scores = {}
        if self.httpd:
            if proto == 'h3':
                port = self.env.h3_port
                via = 'nghttpx'
                descr = f'port {port}, proxying httpd'
            else:
                port = self.env.https_port
                via = 'httpd'
                descr = f'port {port}'
            self.info(f'{via} requests\n')
            self._make_docs_file(docs_dir=self.httpd.docs_dir,
                                 fname='reqs10.data', fsize=10*1024)
            url1 = f'https://{self.env.domain1}:{port}/reqs10.data'
            scores[via] = {
                'description': descr,
                '10KB': self.requests_url(url=url1, proto=proto, count=10000),
            }
        if self.caddy:
            port = self.caddy.port
            via = 'caddy'
            descr = f'port {port}'
            self.info('caddy requests\n')
            self._make_docs_file(docs_dir=self.caddy.docs_dir,
                                 fname='req10.data', fsize=10 * 1024)
            url1 = f'https://{self.env.domain1}:{port}/req10.data'
            scores[via] = {
                'description': descr,
                '10KB': self.requests_url(url=url1, proto=proto, count=5000),
            }
        return scores

    def score_proto(self, proto: str,
                    handshakes: bool = True,
                    downloads: Optional[List[int]] = None,
                    download_count: int = 50,
                    requests: bool = True):
        self.info(f"scoring {proto}\n")
        p = {}
        if proto == 'h3':
            p['name'] = 'h3'
            if not self.env.have_h3_curl():
                raise ScoreCardException('curl does not support HTTP/3')
            for lib in ['ngtcp2', 'quiche', 'msh3']:
                if self.env.curl_uses_lib(lib):
                    p['implementation'] = lib
                    break
        elif proto == 'h2':
            p['name'] = 'h2'
            if not self.env.have_h2_curl():
                raise ScoreCardException('curl does not support HTTP/2')
            for lib in ['nghttp2', 'hyper']:
                if self.env.curl_uses_lib(lib):
                    p['implementation'] = lib
                    break
        elif proto == 'h1' or proto == 'http/1.1':
            proto = 'http/1.1'
            p['name'] = proto
            p['implementation'] = 'hyper' if self.env.curl_uses_lib('hyper')\
                else 'native'
        else:
            raise ScoreCardException(f"unknown protocol: {proto}")

        if 'implementation' not in p:
            raise ScoreCardException(f'did not recognized {p} lib')
        p['version'] = Env.curl_lib_version(p['implementation'])

        score = {
            'curl': self.env.curl_fullname(),
            'os': self.env.curl_os(),
            'protocol': p,
        }
        if handshakes:
            score['handshakes'] = self.handshakes(proto=proto)
        if downloads and len(downloads) > 0:
            score['downloads'] = self.downloads(proto=proto,
                                                count=download_count,
                                                fsizes=downloads)
        if requests:
            score['requests'] = self.requests(proto=proto)
        self.info("\n")
        return score

    def fmt_ms(self, tval):
        return f'{int(tval*1000)} ms' if tval >= 0 else '--'

    def fmt_mb(self, val):
        return f'{val/(1024*1024):0.000f} MB' if val >= 0 else '--'

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
            print('Downloads')
            print(f'  {"Server":<8} {"Size":>8} {"Single":>12} {"Serial":>12}'
                  f' {"Parallel":>12}    {"Errors":<20}')
            skeys = {}
            for dkey, dval in score["downloads"].items():
                for k in dval.keys():
                    skeys[k] = True
            for skey in skeys:
                for dkey, dval in score["downloads"].items():
                    if skey in dval:
                        sval = dval[skey]
                        if isinstance(sval, str):
                            continue
                        errors = []
                        for key, val in sval.items():
                            if 'errors' in val:
                                errors.extend(val['errors'])
                        print(f'  {dkey:<8} {skey:>8} '
                              f'{self.fmt_mbs(sval["single"]["speed"]):>12} '
                              f'{self.fmt_mbs(sval["serial"]["speed"]):>12} '
                              f'{self.fmt_mbs(sval["parallel"]["speed"]):>12} '
                              f'   {"/".join(errors):<20}')
        if 'requests' in score:
            print('Requests, max in parallel')
            print(f'  {"Server":<8} {"Size":>8} '
                  f'{"1    ":>12} {"6    ":>12} {"25    ":>12} '
                  f'{"50    ":>12} {"100    ":>12}    {"Errors":<20}')
            for dkey, dval in score["requests"].items():
                for skey, sval in dval.items():
                    if isinstance(sval, str):
                        continue
                    errors = []
                    for key, val in sval.items():
                        if 'errors' in val:
                            errors.extend(val['errors'])
                    line = f'  {dkey:<8} {skey:>8} '
                    for k in sval.keys():
                        line += f'{self.fmt_reqs(sval[k]["speed"]):>12} '
                    line += f'   {"/".join(errors):<20}'
                    print(line)


def parse_size(s):
    m = re.match(r'(\d+)(mb|kb|gb)?', s, re.IGNORECASE)
    if m is None:
        raise Exception(f'unrecognized size: {s}')
    size = int(m.group(1))
    if m.group(2).lower() == 'kb':
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
                        default=False, help="evaluate downloads only")
    parser.add_argument("--download", action='append', type=str,
                        default=None, help="evaluate download size")
    parser.add_argument("--download-count", action='store', type=int,
                        default=50, help="perform that many downloads")
    parser.add_argument("-r", "--requests", action='store_true',
                        default=False, help="evaluate requests only")
    parser.add_argument("--httpd", action='store_true', default=False,
                        help="evaluate httpd server only")
    parser.add_argument("--caddy", action='store_true', default=False,
                        help="evaluate caddy server only")
    parser.add_argument("--curl-verbose", action='store_true',
                        default=False, help="run curl with `-v`")
    parser.add_argument("protocol", default='h2', nargs='?',
                        help="Name of protocol to score")
    args = parser.parse_args()

    if args.verbose > 0:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logging.getLogger('').addHandler(console)

    protocol = args.protocol
    handshakes = True
    downloads = [1024*1024, 10*1024*1024, 100*1024*1024]
    requests = True
    test_httpd = protocol != 'h3'
    test_caddy = True
    if args.handshakes:
        downloads = None
        requests = False
    if args.downloads:
        handshakes = False
        requests = False
    if args.download:
        downloads = sorted([parse_size(x) for x in args.download])
        handshakes = False
        requests = False
    if args.requests:
        handshakes = False
        downloads = None
    if args.caddy:
        test_caddy = True
        test_httpd = False
    if args.httpd:
        test_caddy = False
        test_httpd = True

    rv = 0
    env = Env()
    env.setup()
    env.test_timeout = None
    httpd = None
    nghttpx = None
    caddy = None
    try:
        if test_httpd:
            httpd = Httpd(env=env)
            assert httpd.exists(), \
                f'httpd not found: {env.httpd}'
            httpd.clear_logs()
            assert httpd.start()
            if 'h3' == protocol:
                nghttpx = Nghttpx(env=env)
                nghttpx.clear_logs()
                assert nghttpx.start()
        if test_caddy and env.caddy:
            caddy = Caddy(env=env)
            caddy.clear_logs()
            assert caddy.start()

        card = ScoreCard(env=env, httpd=httpd, nghttpx=nghttpx, caddy=caddy,
                         verbose=args.verbose, curl_verbose=args.curl_verbose)
        score = card.score_proto(proto=protocol,
                                 handshakes=handshakes,
                                 downloads=downloads,
                                 download_count=args.download_count,
                                 requests=requests)
        if args.json:
            print(json.JSONEncoder(indent=2).encode(score))
        else:
            card.print_score(score)

    except ScoreCardException as ex:
        sys.stderr.write(f"ERROR: {str(ex)}\n")
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
