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
import logging
import os
import re
import subprocess
from configparser import ConfigParser, ExtendedInterpolation
from typing import Optional

from .certs import CertificateSpec, TestCA, Credentials

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
        self.config = DEF_CONFIG
        # check cur and its features
        self.curl = CURL
        self.curl_props = {
            'version': None,
            'os': None,
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
                    self.curl_props['version'] = m.group('version')
                    self.curl_props['os'] = m.group('os')
                    self.curl_props['lib_versions'] = [
                        lib.lower() for lib in m.group('libs').split(' ')
                    ]
                    self.curl_props['libs'] = [
                        re.sub(r'/.*', '',lib) for lib in self.curl_props['lib_versions']
                    ]
            if l.startswith('Features: '):
                self.curl_props['features'] = [
                    feat.lower() for feat in l[10:].split(' ')
                ]
            if l.startswith('Protocols: '):
                self.curl_props['protocols'] =  [
                    prot.lower() for prot in l[11:].split(' ')
                ]
        self.nghttpx_with_h3 = re.match(r'.* nghttp3/.*', p.stdout.strip())
        log.debug(f'nghttpx -v: {p.stdout}')

        self.http_port = self.config['test']['http_port']
        self.https_port = self.config['test']['https_port']
        self.h3_port = self.config['test']['h3_port']
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
        self.tld = 'tests-httpd.curl.se'
        self.domain1 = f"one.{self.tld}"
        self.domain2 = f"two.{self.tld}"
        self.cert_specs = [
            CertificateSpec(domains=[self.domain1], key_type='rsa2048'),
            CertificateSpec(domains=[self.domain2], key_type='rsa2048'),
            CertificateSpec(name="clientsX", sub_specs=[
               CertificateSpec(name="user1", client=True),
            ]),
        ]

        self.nghttpx = self.config['nghttpx']['nghttpx']
        self.nghttpx_with_h3 = False
        if len(self.nghttpx) == 0:
            self.nghttpx = 'nghttpx'
        if self.nghttpx is not None:
            p = subprocess.run(args=[self.nghttpx, '-v'],
                               capture_output=True, text=True)
            if p.returncode != 0:
                # not a working nghttpx
                self.nghttpx = None
            else:
                self.nghttpx_with_h3 = re.match(r'.* nghttp3/.*', p.stdout.strip()) is not None
                log.debug(f'nghttpx -v: {p.stdout}')

        self.caddy = self.config['caddy']['caddy']
        if len(self.caddy) == 0:
            self.caddy = 'caddy'
        if self.caddy is not None:
            try:
                p = subprocess.run(args=[self.caddy, 'version'],
                                   capture_output=True, text=True)
                if p.returncode != 0:
                    # not a working caddy
                    self.caddy = None
            except:
                self.caddy = None
        self.caddy_port = self.config['caddy']['port']

    @property
    def httpd_version(self):
        if self._httpd_version is None and self.apxs is not None:
            p = subprocess.run(args=[self.apxs, '-q', 'HTTPD_VERSION'],
                               capture_output=True, text=True)
            if p.returncode != 0:
                raise Exception(f'{self.apxs} failed to query HTTPD_VERSION: {p}')
            self._httpd_version = p.stdout.strip()
        return self._httpd_version

    def _versiontuple(self, v):
        v = re.sub(r'(\d+\.\d+(\.\d+)?)(-\S+)?', r'\1', v)
        return tuple(map(int, v.split('.')))

    def httpd_is_at_least(self, minv):
        hv = self._versiontuple(self.httpd_version)
        return hv >= self._versiontuple(minv)

    def is_complete(self) -> bool:
        return os.path.isfile(self.httpd) and \
               os.path.isfile(self.apachectl) and \
               self.apxs is not None and \
               os.path.isfile(self.apxs)

    def get_incomplete_reason(self) -> Optional[str]:
        if not os.path.isfile(self.httpd):
            return f'httpd ({self.httpd}) not found'
        if not os.path.isfile(self.apachectl):
            return f'apachectl ({self.apachectl}) not found'
        if self.apxs is None:
            return f"apxs (provided by apache2-dev) not found"
        if not os.path.isfile(self.apxs):
            return f"apxs ({self.apxs}) not found"
        return None


class Env:

    CONFIG = EnvConfig()

    @staticmethod
    def setup_incomplete() -> bool:
        return not Env.CONFIG.is_complete()

    @staticmethod
    def incomplete_reason() -> Optional[str]:
        return Env.CONFIG.get_incomplete_reason()

    @staticmethod
    def have_h3_server() -> bool:
        return Env.CONFIG.nghttpx_with_h3

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
    def curl_lib_version(libname: str) -> str:
        prefix = f'{libname.lower()}/'
        for lversion in Env.CONFIG.curl_props['lib_versions']:
            if lversion.startswith(prefix):
                return lversion[len(prefix):]
        return 'unknown'

    @staticmethod
    def curl_os() -> bool:
        return Env.CONFIG.curl_props['os']

    @staticmethod
    def curl_version() -> bool:
        return Env.CONFIG.curl_props['version']

    @staticmethod
    def have_h3() -> bool:
        return Env.have_h3_curl() and Env.have_h3_server()

    @staticmethod
    def httpd_version() -> str:
        return Env.CONFIG.httpd_version

    @staticmethod
    def httpd_is_at_least(minv) -> bool:
        return Env.CONFIG.httpd_is_at_least(minv)

    def __init__(self, pytestconfig=None):
        self._verbose = pytestconfig.option.verbose \
            if pytestconfig is not None else 0
        self._ca = None

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
    def gen_dir(self) -> str:
        return self.CONFIG.gen_dir

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
    def http_port(self) -> str:
        return self.CONFIG.http_port

    @property
    def https_port(self) -> str:
        return self.CONFIG.https_port

    @property
    def h3_port(self) -> str:
        return self.CONFIG.h3_port

    @property
    def caddy(self) -> str:
        return self.CONFIG.caddy

    @property
    def caddy_port(self) -> str:
        return self.CONFIG.caddy_port

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
