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
import re
import socket
import subprocess
import sys
from configparser import ConfigParser, ExtendedInterpolation
from typing import Optional

import pytest

from .certs import CertificateSpec, TestCA, Credentials
from .ports import alloc_ports


log = logging.getLogger(__name__)


def init_config_from(conf_path):
    if os.path.isfile(conf_path):
        config = ConfigParser(interpolation=ExtendedInterpolation())
        config.read(conf_path)
        return config
    return None


TESTS_HTTPD_PATH = os.path.dirname(os.path.dirname(__file__))
DEF_CONFIG = init_config_from(os.path.join(TESTS_HTTPD_PATH, 'config.ini'))

TOP_PATH = os.path.dirname(os.path.dirname(TESTS_HTTPD_PATH))
CURL = os.path.join(TOP_PATH, 'src/curl')


class EnvConfig:

    def __init__(self):
        self.tests_dir = TESTS_HTTPD_PATH
        self.gen_dir = os.path.join(self.tests_dir, 'gen')
        self.project_dir = os.path.dirname(os.path.dirname(self.tests_dir))
        self.config = DEF_CONFIG
        # check cur and its features
        self.curl = CURL
        if 'CURL' in os.environ:
            self.curl = os.environ['CURL']
        self.curl_props = {
            'version': None,
            'os': None,
            'fullname': None,
            'features': [],
            'protocols': [],
            'libs': [],
            'lib_versions': [],
        }
        self.curl_protos = []
        p = subprocess.run(args=[self.curl, '-V'],
                           capture_output=True, text=True)
        if p.returncode != 0:
            assert False, f'{self.curl} -V failed with exit code: {p.returncode}'
        for l in p.stdout.splitlines(keepends=False):
            if l.startswith('curl '):
                m = re.match(r'^curl (?P<version>\S+) (?P<os>\S+) (?P<libs>.*)$', l)
                if m:
                    self.curl_props['fullname'] = m.group(0)
                    self.curl_props['version'] = m.group('version')
                    self.curl_props['os'] = m.group('os')
                    self.curl_props['lib_versions'] = [
                        lib.lower() for lib in m.group('libs').split(' ')
                    ]
                    self.curl_props['libs'] = [
                        re.sub(r'/.*', '', lib) for lib in self.curl_props['lib_versions']
                    ]
            if l.startswith('Features: '):
                self.curl_props['features'] = [
                    feat.lower() for feat in l[10:].split(' ')
                ]
            if l.startswith('Protocols: '):
                self.curl_props['protocols'] = [
                    prot.lower() for prot in l[11:].split(' ')
                ]

        self.ports = alloc_ports(port_specs={
            'http': socket.SOCK_STREAM,
            'https': socket.SOCK_STREAM,
            'proxy': socket.SOCK_STREAM,
            'proxys': socket.SOCK_STREAM,
            'h2proxys': socket.SOCK_STREAM,
            'caddy': socket.SOCK_STREAM,
            'caddys': socket.SOCK_STREAM,
            'ws': socket.SOCK_STREAM,
        })
        self.httpd = self.config['httpd']['httpd']
        self.apachectl = self.config['httpd']['apachectl']
        self.apxs = self.config['httpd']['apxs']
        if len(self.apxs) == 0:
            self.apxs = None
        self._httpd_version = None

        self.examples_pem = {
            'key': 'xxx',
            'cert': 'xxx',
        }
        self.htdocs_dir = os.path.join(self.gen_dir, 'htdocs')
        self.tld = 'http.curl.se'
        self.domain1 = f"one.{self.tld}"
        self.domain2 = f"two.{self.tld}"
        self.proxy_domain = f"proxy.{self.tld}"
        self.cert_specs = [
            CertificateSpec(domains=[self.domain1, 'localhost'], key_type='rsa2048'),
            CertificateSpec(domains=[self.domain2], key_type='rsa2048'),
            CertificateSpec(domains=[self.proxy_domain], key_type='rsa2048'),
            CertificateSpec(name="clientsX", sub_specs=[
               CertificateSpec(name="user1", client=True),
            ]),
        ]

        self.nghttpx = self.config['nghttpx']['nghttpx']
        if len(self.nghttpx.strip()) == 0:
            self.nghttpx = None
        self._nghttpx_version = None
        self.nghttpx_with_h3 = False
        if self.nghttpx is not None:
            p = subprocess.run(args=[self.nghttpx, '-v'],
                               capture_output=True, text=True)
            if p.returncode != 0:
                # not a working nghttpx
                self.nghttpx = None
            else:
                self._nghttpx_version = re.sub(r'^nghttpx\s*', '', p.stdout.strip())
                self.nghttpx_with_h3 = re.match(r'.* nghttp3/.*', p.stdout.strip()) is not None
                log.debug(f'nghttpx -v: {p.stdout}')

        self.caddy = self.config['caddy']['caddy']
        self._caddy_version = None
        if len(self.caddy.strip()) == 0:
            self.caddy = None
        if self.caddy is not None:
            try:
                p = subprocess.run(args=[self.caddy, 'version'],
                                   capture_output=True, text=True)
                if p.returncode != 0:
                    # not a working caddy
                    self.caddy = None
                self._caddy_version = re.sub(r' .*', '', p.stdout.strip())
            except:
                self.caddy = None

    @property
    def httpd_version(self):
        if self._httpd_version is None and self.apxs is not None:
            try:
                p = subprocess.run(args=[self.apxs, '-q', 'HTTPD_VERSION'],
                                   capture_output=True, text=True)
                if p.returncode != 0:
                    log.error(f'{self.apxs} failed to query HTTPD_VERSION: {p}')
                else:
                    self._httpd_version = p.stdout.strip()
            except Exception as e:
                log.error(f'{self.apxs} failed to run: {e}')
        return self._httpd_version

    def _versiontuple(self, v):
        v = re.sub(r'(\d+\.\d+(\.\d+)?)(-\S+)?', r'\1', v)
        return tuple(map(int, v.split('.')))

    def httpd_is_at_least(self, minv):
        if self.httpd_version is None:
            return False
        hv = self._versiontuple(self.httpd_version)
        return hv >= self._versiontuple(minv)

    def is_complete(self) -> bool:
        return os.path.isfile(self.httpd) and \
               os.path.isfile(self.apachectl) and \
               self.apxs is not None and \
               os.path.isfile(self.apxs)

    def get_incomplete_reason(self) -> Optional[str]:
        if self.httpd is None or len(self.httpd.strip()) == 0:
            return f'httpd not configured, see `--with-test-httpd=<path>`'
        if not os.path.isfile(self.httpd):
            return f'httpd ({self.httpd}) not found'
        if not os.path.isfile(self.apachectl):
            return f'apachectl ({self.apachectl}) not found'
        if self.apxs is None:
            return f"command apxs not found (commonly provided in apache2-dev)"
        if not os.path.isfile(self.apxs):
            return f"apxs ({self.apxs}) not found"
        return None

    @property
    def nghttpx_version(self):
        return self._nghttpx_version

    @property
    def caddy_version(self):
        return self._caddy_version


class Env:

    CONFIG = EnvConfig()

    @staticmethod
    def setup_incomplete() -> bool:
        return not Env.CONFIG.is_complete()

    @staticmethod
    def incomplete_reason() -> Optional[str]:
        return Env.CONFIG.get_incomplete_reason()

    @staticmethod
    def have_nghttpx() -> bool:
        return Env.CONFIG.nghttpx is not None

    @staticmethod
    def have_h3_server() -> bool:
        return Env.CONFIG.nghttpx_with_h3

    @staticmethod
    def have_ssl_curl() -> bool:
        return 'ssl' in Env.CONFIG.curl_props['features']

    @staticmethod
    def have_h2_curl() -> bool:
        return 'http2' in Env.CONFIG.curl_props['features']

    @staticmethod
    def have_h3_curl() -> bool:
        return 'http3' in Env.CONFIG.curl_props['features']

    @staticmethod
    def curl_uses_lib(libname: str) -> bool:
        return libname.lower() in Env.CONFIG.curl_props['libs']

    @staticmethod
    def curl_has_feature(feature: str) -> bool:
        return feature.lower() in Env.CONFIG.curl_props['features']

    @staticmethod
    def curl_has_protocol(protocol: str) -> bool:
        return protocol.lower() in Env.CONFIG.curl_props['protocols']

    @staticmethod
    def curl_lib_version(libname: str) -> str:
        prefix = f'{libname.lower()}/'
        for lversion in Env.CONFIG.curl_props['lib_versions']:
            if lversion.startswith(prefix):
                return lversion[len(prefix):]
        return 'unknown'

    @staticmethod
    def curl_os() -> str:
        return Env.CONFIG.curl_props['os']

    @staticmethod
    def curl_fullname() -> str:
        return Env.CONFIG.curl_props['fullname']

    @staticmethod
    def curl_version() -> str:
        return Env.CONFIG.curl_props['version']

    @staticmethod
    def have_h3() -> bool:
        return Env.have_h3_curl() and Env.have_h3_server()

    @staticmethod
    def httpd_version() -> str:
        return Env.CONFIG.httpd_version

    @staticmethod
    def nghttpx_version() -> str:
        return Env.CONFIG.nghttpx_version

    @staticmethod
    def caddy_version() -> str:
        return Env.CONFIG.caddy_version

    @staticmethod
    def httpd_is_at_least(minv) -> bool:
        return Env.CONFIG.httpd_is_at_least(minv)

    @staticmethod
    def has_caddy() -> bool:
        return Env.CONFIG.caddy is not None

    def __init__(self, pytestconfig=None):
        self._verbose = pytestconfig.option.verbose \
            if pytestconfig is not None else 0
        self._ca = None
        self._test_timeout = 300.0 if self._verbose > 1 else 60.0  # seconds

    def issue_certs(self):
        if self._ca is None:
            ca_dir = os.path.join(self.CONFIG.gen_dir, 'ca')
            self._ca = TestCA.create_root(name=self.CONFIG.tld,
                                          store_dir=ca_dir,
                                          key_type="rsa2048")
        self._ca.issue_certs(self.CONFIG.cert_specs)

    def setup(self):
        os.makedirs(self.gen_dir, exist_ok=True)
        os.makedirs(self.htdocs_dir, exist_ok=True)
        self.issue_certs()

    def get_credentials(self, domain) -> Optional[Credentials]:
        creds = self.ca.get_credentials_for_name(domain)
        if len(creds) > 0:
            return creds[0]
        return None

    @property
    def verbose(self) -> int:
        return self._verbose

    @property
    def test_timeout(self) -> Optional[float]:
        return self._test_timeout

    @test_timeout.setter
    def test_timeout(self, val: Optional[float]):
        self._test_timeout = val

    @property
    def gen_dir(self) -> str:
        return self.CONFIG.gen_dir

    @property
    def project_dir(self) -> str:
        return self.CONFIG.project_dir

    @property
    def ca(self):
        return self._ca

    @property
    def htdocs_dir(self) -> str:
        return self.CONFIG.htdocs_dir

    @property
    def domain1(self) -> str:
        return self.CONFIG.domain1

    @property
    def domain2(self) -> str:
        return self.CONFIG.domain2

    @property
    def proxy_domain(self) -> str:
        return self.CONFIG.proxy_domain

    @property
    def http_port(self) -> int:
        return self.CONFIG.ports['http']

    @property
    def https_port(self) -> int:
        return self.CONFIG.ports['https']

    @property
    def h3_port(self) -> int:
        return self.https_port

    @property
    def proxy_port(self) -> int:
        return self.CONFIG.ports['proxy']

    @property
    def proxys_port(self) -> int:
        return self.CONFIG.ports['proxys']

    @property
    def h2proxys_port(self) -> int:
        return self.CONFIG.ports['h2proxys']

    def pts_port(self, proto: str = 'http/1.1') -> int:
        # proxy tunnel port
        return self.CONFIG.ports['h2proxys' if proto == 'h2' else 'proxys']

    @property
    def caddy(self) -> str:
        return self.CONFIG.caddy

    @property
    def caddy_https_port(self) -> int:
        return self.CONFIG.ports['caddys']

    @property
    def caddy_http_port(self) -> int:
        return self.CONFIG.ports['caddy']

    @property
    def ws_port(self) -> int:
        return self.CONFIG.ports['ws']

    @property
    def curl(self) -> str:
        return self.CONFIG.curl

    @property
    def httpd(self) -> str:
        return self.CONFIG.httpd

    @property
    def apachectl(self) -> str:
        return self.CONFIG.apachectl

    @property
    def apxs(self) -> str:
        return self.CONFIG.apxs

    @property
    def nghttpx(self) -> Optional[str]:
        return self.CONFIG.nghttpx

    def authority_for(self, domain: str, alpn_proto: Optional[str] = None):
        if alpn_proto is None or \
                alpn_proto in ['h2', 'http/1.1', 'http/1.0', 'http/0.9']:
            return f'{domain}:{self.https_port}'
        if alpn_proto in ['h3']:
            return f'{domain}:{self.h3_port}'
        return f'{domain}:{self.http_port}'

    def make_data_file(self, indir: str, fname: str, fsize: int) -> str:
        fpath = os.path.join(indir, fname)
        s10 = "0123456789"
        s = (101 * s10) + s10[0:3]
        with open(fpath, 'w') as fd:
            for i in range(int(fsize / 1024)):
                fd.write(f"{i:09d}-{s}\n")
            remain = int(fsize % 1024)
            if remain != 0:
                i = int(fsize / 1024) + 1
                s = f"{i:09d}-{s}\n"
                fd.write(s[0:remain])
        return fpath

    def make_clients(self):
        client_dir = os.path.join(self.project_dir, 'tests/http/clients')
        p = subprocess.run(['make'], capture_output=True, text=True,
                           cwd=client_dir)
        if p.returncode != 0:
            pytest.exit(f"`make`in {client_dir} failed:\n{p.stderr}")
            return False
        return True

