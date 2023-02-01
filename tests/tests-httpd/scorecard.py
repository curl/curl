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
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from statistics import mean
from typing import Dict, Any

from testenv import Env, Httpd, Nghttpx, CurlClient, Caddy, ExecResult


log = logging.getLogger(__name__)


class ScoreCardException(Exception):
    pass


class ScoreCard:

    def __init__(self):
        self.verbose = 0
        self.env = None
        self.httpd = None
        self.nghttpx = None
        self.caddy = None

    def info(self, msg):
        if self.verbose > 0:
            sys.stderr.write(msg)
            sys.stderr.flush()

    def handshakes(self, proto: str) -> Dict[str, Any]:
        props = {}
        sample_size = 10
        self.info(f'handshaking ')
        for authority in [
            f'{self.env.authority_for(self.env.domain1, proto)}'
        ]:
            self.info('localhost')
            c_samples = []
            hs_samples = []
            errors = []
            for i in range(sample_size):
                self.info('.')
                curl = CurlClient(env=self.env)
                url = f'https://{authority}/'
                r = curl.http_download(urls=[url], alpn_proto=proto)
                if r.exit_code == 0 and len(r.stats) == 1:
                    c_samples.append(r.stats[0]['time_connect'])
                    hs_samples.append(r.stats[0]['time_appconnect'])
                else:
                    errors.append(f'exit={r.exit_code}')
            props['localhost'] = {
                'connect': mean(c_samples),
                'handshake': mean(hs_samples),
                'errors': errors
            }
        for authority in [
            'curl.se', 'google.com', 'cloudflare.com', 'nghttp2.org',
        ]:
            for ipv in ['ipv4', 'ipv6']:
                self.info(f'{authority}-{ipv}')
                c_samples = []
                hs_samples = []
                errors = []
                for i in range(sample_size):
                    self.info('.')
                    curl = CurlClient(env=self.env)
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
                props[f'{authority}-{ipv}'] = {
                    'connect': mean(c_samples) if len(c_samples) else -1,
                    'handshake': mean(hs_samples) if len(hs_samples) else -1,
                    'errors': errors
                }
        self.info('\n')
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
        self.info(f'{sample_size}x single')
        for i in range(sample_size):
            curl = CurlClient(env=self.env)
            r = curl.http_download(urls=[url], alpn_proto=proto)
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                samples.append(r.stats[0]['speed_download'])
        self.info(f'.')
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
        self.info(f'{sample_size}x{count} serial')
        for i in range(sample_size):
            curl = CurlClient(env=self.env)
            r = curl.http_download(urls=[url], alpn_proto=proto)
            self.info(f'.')
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                for s in r.stats:
                    samples.append(s['speed_download'])
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
        self.info(f'{sample_size}x{count} parallel')
        for i in range(sample_size):
            curl = CurlClient(env=self.env)
            start = datetime.now()
            r = curl.http_download(urls=[url], alpn_proto=proto,
                                   extra_args=['--parallel'])
            err = self._check_downloads(r, count)
            if err:
                errors.append(err)
            else:
                duration = datetime.now() - start
                total_size = sum([s['size_download'] for s in r.stats])
                samples.append(total_size / duration.total_seconds())
        return {
            'count': count,
            'samples': sample_size,
            'speed': mean(samples) if len(samples) else -1,
            'errors': errors
        }

    def download_url(self, url: str, proto: str, count: int):
        self.info(f'  {url}: ')
        props = {
            'single': self.transfer_single(url=url, proto=proto, count=10),
            'serial': self.transfer_serial(url=url, proto=proto, count=count),
            'parallel': self.transfer_parallel(url=url, proto=proto, count=count),
        }
        self.info(f'\n')
        return props

    def downloads(self, proto: str) -> Dict[str, Any]:
        scores = {}
        if proto == 'h3':
            port = self.env.h3_port
            via = 'nghttpx'
            descr = f'port {port}, proxying httpd'
        else:
            port = self.env.https_port
            via = 'httpd'
            descr = f'port {port}'
        self.info('httpd downloads\n')
        self._make_docs_file(docs_dir=self.httpd.docs_dir, fname='score1.data', fsize=1024*1024)
        url1 = f'https://{self.env.domain1}:{port}/score1.data'
        self._make_docs_file(docs_dir=self.httpd.docs_dir, fname='score10.data', fsize=10*1024*1024)
        url10 = f'https://{self.env.domain1}:{port}/score10.data'
        self._make_docs_file(docs_dir=self.httpd.docs_dir, fname='score100.data', fsize=100*1024*1024)
        url100 = f'https://{self.env.domain1}:{port}/score100.data'
        scores[via] = {
            'description': descr,
            '1MB-local': self.download_url(url=url1, proto=proto, count=50),
            '10MB-local': self.download_url(url=url10, proto=proto, count=50),
            '100MB-local': self.download_url(url=url100, proto=proto, count=50),
        }
        if self.caddy:
            port = self.env.caddy_port
            via = 'caddy'
            descr = f'port {port}'
            self.info('caddy downloads\n')
            self._make_docs_file(docs_dir=self.caddy.docs_dir, fname='score1.data', fsize=1024 * 1024)
            url1 = f'https://{self.env.domain1}:{port}/score1.data'
            self._make_docs_file(docs_dir=self.caddy.docs_dir, fname='score10.data', fsize=10 * 1024 * 1024)
            url10 = f'https://{self.env.domain1}:{port}/score10.data'
            self._make_docs_file(docs_dir=self.caddy.docs_dir, fname='score100.data', fsize=100 * 1024 * 1024)
            url100 = f'https://{self.env.domain1}:{port}/score100.data'
            scores[via] = {
                'description': descr,
                '1MB-local': self.download_url(url=url1, proto=proto, count=50),
                '10MB-local': self.download_url(url=url10, proto=proto, count=50),
                '100MB-local': self.download_url(url=url100, proto=proto, count=50),
            }
        return scores

    def score_proto(self, proto: str, handshakes: bool = True, downloads: bool = True):
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
        else:
            raise ScoreCardException(f"unknown protocol: {proto}")

        if 'implementation' not in p:
            raise ScoreCardException(f'did not recognized {p} lib')
        p['version'] = Env.curl_lib_version(p['implementation'])

        score = {
            'curl': self.env.curl_version(),
            'os': self.env.curl_os(),
            'protocol': p,
        }
        if handshakes:
            score['handshakes'] = self.handshakes(proto=proto)
        if downloads:
            score['downloads'] = self.downloads(proto=proto)
        self.info("\n")
        return score

    def fmt_ms(self, tval):
        return f'{int(tval*1000)} ms' if tval >= 0 else '--'

    def fmt_mb(self, val):
        return f'{val/(1024*1024):0.000f} MB' if val >= 0 else '--'

    def fmt_mbs(self, val):
        return f'{val/(1024*1024):0.000f} MB/s' if val >= 0 else '--'

    def print_score(self, score):
        print(f'{score["protocol"]["name"].upper()} in curl {score["curl"]} ({score["os"]}) via '
              f'{score["protocol"]["implementation"]}/{score["protocol"]["version"]} ')
        if 'handshakes' in score:
            print('Handshakes')
            print(f'  {"Host":<25} {"Connect":>12} {"Handshake":>12}     {"Errors":<20}')
            for key, val in score["handshakes"].items():
                print(f'  {key:<25} {self.fmt_ms(val["connect"]):>12} '''
                      f'{self.fmt_ms(val["handshake"]):>12}     {"/".join(val["errors"]):<20}')
        if 'downloads' in score:
            print('Downloads')
            for dkey, dval in score["downloads"].items():
                print(f'  {dkey}: {dval["description"]}')
                for skey, sval in dval.items():
                    if isinstance(sval, str):
                        continue
                    print(f'    {skey:<13} {"Samples":>10} {"Count":>10} {"Speed":>17}   {"Errors":<20}')
                    for key, val in sval.items():
                        print(f'      {key:<11} {val["samples"]:>10} '''
                              f'{val["count"]:>10} {self.fmt_mbs(val["speed"]):>17}   '
                              f'{"/".join(val["errors"]):<20}')

    def main(self):
        parser = argparse.ArgumentParser(prog='scorecard', description="""
            Run a range of tests to give a scorecard for a HTTP protocol
            'h3' or 'h2' implementation in curl.
            """)
        parser.add_argument("-v", "--verbose", action='count', default=0,
                            help="log more output on stderr")
        parser.add_argument("-t", "--text", action='store_true', default=False,
                            help="print text instead of json")
        parser.add_argument("-d", "--downloads", action='store_true', default=False,
                            help="evaluate downloads only")
        parser.add_argument("protocols", nargs='*', help="Name(s) of protocol to score")
        args = parser.parse_args()

        self.verbose = args.verbose
        if args.verbose > 0:
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
            logging.getLogger('').addHandler(console)

        protocols = args.protocols if len(args.protocols) else ['h2', 'h3']
        handshakes = True
        downloads = True
        if args.downloads:
            handshakes = False

        rv = 0
        self.env = Env()
        self.env.setup()
        self.httpd = None
        self.nghttpx = None
        self.caddy = None
        try:
            self.httpd = Httpd(env=self.env)
            assert self.httpd.exists(), f'httpd not found: {self.env.httpd}'
            self.httpd.clear_logs()
            assert self.httpd.start()
            if 'h3' in protocols:
                self.nghttpx = Nghttpx(env=self.env)
                self.nghttpx.clear_logs()
                assert self.nghttpx.start()
            if self.env.caddy:
                self.caddy = Caddy(env=self.env)
                self.caddy.clear_logs()
                assert self.caddy.start()

            for p in protocols:
                score = self.score_proto(proto=p, handshakes=handshakes, downloads=downloads)
                if args.text:
                    self.print_score(score)
                else:
                    print(json.JSONEncoder(indent=2).encode(score))

        except ScoreCardException as ex:
            sys.stderr.write(f"ERROR: {str(ex)}\n")
            rv = 1
        except KeyboardInterrupt:
            log.warning("aborted")
            rv = 1
        finally:
            if self.caddy:
                self.caddy.stop()
                self.caddy = None
            if self.nghttpx:
                self.nghttpx.stop(wait_dead=False)
            if self.httpd:
                self.httpd.stop()
                self.httpd = None
        sys.exit(rv)


if __name__ == "__main__":
    ScoreCard().main()
