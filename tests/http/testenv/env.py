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
import gzip
import logging
import os
import re
import shutil
import subprocess
import tempfile
from configparser import ConfigParser, ExtendedInterpolation
from datetime import timedelta
from typing import Optional, Dict, List

import pytest
from filelock import FileLock

from .certs import CertificateSpec, Credentials, TestCA


log = logging.getLogger(__name__)


def init_config_from(conf_path):
    if os.path.isfile(conf_path):
        config = ConfigParser(interpolation=ExtendedInterpolation())
        config.read(conf_path)
        return config
    return None


TESTS_HTTPD_PATH = os.path.dirname(os.path.dirname(__file__))
PROJ_PATH = os.path.dirname(os.path.dirname(TESTS_HTTPD_PATH))
TOP_PATH = os.path.join(os.getcwd(), os.path.pardir)
CONFIG_PATH = os.path.join(TOP_PATH, 'tests', 'http', 'config.ini')
if not os.path.exists(CONFIG_PATH):
    ALT_CONFIG_PATH = os.path.join(PROJ_PATH, 'tests', 'http', 'config.ini')
    if not os.path.exists(ALT_CONFIG_PATH):
        raise Exception(f'unable to find config.ini in {CONFIG_PATH} nor {ALT_CONFIG_PATH}')
    TOP_PATH = PROJ_PATH
    CONFIG_PATH = ALT_CONFIG_PATH
DEF_CONFIG = init_config_from(CONFIG_PATH)
CURL = os.path.join(TOP_PATH, 'src', 'curl')


class NghttpxUtil:

    CMD = None
    VERSION_FULL = None

    @classmethod
    def version(cls, cmd):
        if cmd is None:
            return None
        if cls.VERSION_FULL is None or cmd != cls.CMD:
            p = subprocess.run(args=[cmd, '--version'],
                               capture_output=True, text=True)
            if p.returncode != 0:
                raise RuntimeError(f'{cmd} --version failed with exit code: {p.returncode}')
            cls.CMD = cmd
            for line in p.stdout.splitlines(keepends=False):
                if line.startswith('nghttpx '):
                    cls.VERSION_FULL = line
            if cls.VERSION_FULL is None:
                raise RuntimeError(f'{cmd}: unable to determine version')
        return cls.VERSION_FULL

    @staticmethod
    def version_with_h3(version):
        return re.match(r'.* ngtcp2/\d+\.\d+\.\d+.*', version) is not None


class EnvConfig:

    def __init__(self, pytestconfig: Optional[pytest.Config] = None,
                 testrun_uid=None,
                 worker_id=None):
        self.pytestconfig = pytestconfig
        self.testrun_uid = testrun_uid
        self.worker_id = worker_id if worker_id is not None else 'master'
        self.tests_dir = TESTS_HTTPD_PATH
        self.gen_root = self.gen_dir = os.path.join(self.tests_dir, 'gen')
        if self.worker_id != 'master':
            self.gen_dir = os.path.join(self.gen_dir, self.worker_id)
        self.project_dir = os.path.dirname(os.path.dirname(self.tests_dir))
        self.build_dir = TOP_PATH
        self.config = DEF_CONFIG
        # check cur and its features
        self.curl = CURL
        if 'CURL' in os.environ:
            self.curl = os.environ['CURL']
        self.curl_props = {
            'version_string': '',
            'version': '',
            'os': '',
            'fullname': '',
            'features_string': '',
            'features': set(),
            'protocols_string': '',
            'protocols': set(),
            'libs': set(),
            'lib_versions': set(),
        }
        self.curl_is_debug = False
        self.curl_protos = []
        p = subprocess.run(args=[self.curl, '-V'],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f'{self.curl} -V failed with exit code: {p.returncode}')
        if p.stderr.startswith('WARNING:'):
            self.curl_is_debug = True
        for line in p.stdout.splitlines(keepends=False):
            if line.startswith('curl '):
                self.curl_props['version_string'] = line
                m = re.match(r'^curl (?P<version>\S+) (?P<os>\S+) (?P<libs>.*)$', line)
                if m:
                    self.curl_props['fullname'] = m.group(0)
                    self.curl_props['version'] = m.group('version')
                    self.curl_props['os'] = m.group('os')
                    self.curl_props['lib_versions'] = {
                        lib.lower() for lib in m.group('libs').split(' ')
                    }
                    self.curl_props['libs'] = {
                        re.sub(r'/[a-z0-9.-]*', '', lib) for lib in self.curl_props['lib_versions']
                    }
            if line.startswith('Features: '):
                self.curl_props['features_string'] = line[10:]
                self.curl_props['features'] = {
                    feat.lower() for feat in line[10:].split(' ')
                }
            if line.startswith('Protocols: '):
                self.curl_props['protocols_string'] = line[11:]
                self.curl_props['protocols'] = {
                    prot.lower() for prot in line[11:].split(' ')
                }

        self.ports = {}

        self.httpd = self.config['httpd']['httpd']
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
        self.domain1brotli = f"brotli.one.{self.tld}"
        self.domain2 = f"two.{self.tld}"
        self.ftp_domain = f"ftp.{self.tld}"
        self.proxy_domain = f"proxy.{self.tld}"
        self.expired_domain = f"expired.{self.tld}"
        self.cert_specs = [
            CertificateSpec(domains=[self.domain1, self.domain1brotli, 'localhost', '127.0.0.1'], key_type='rsa2048'),
            CertificateSpec(name='domain1-no-ip', domains=[self.domain1, self.domain1brotli], key_type='rsa2048'),
            CertificateSpec(domains=[self.domain2], key_type='rsa2048'),
            CertificateSpec(domains=[self.ftp_domain], key_type='rsa2048'),
            CertificateSpec(domains=[self.proxy_domain, '127.0.0.1'], key_type='rsa2048'),
            CertificateSpec(domains=[self.expired_domain], key_type='rsa2048',
                            valid_from=timedelta(days=-100), valid_to=timedelta(days=-10)),
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
            try:
                self._nghttpx_version = NghttpxUtil.version(self.nghttpx)
                self.nghttpx_with_h3 = NghttpxUtil.version_with_h3(self._nghttpx_version)
            except RuntimeError:
                # not a working nghttpx
                log.exception('checking nghttpx version')
                self.nghttpx = None

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
                m = re.match(r'v?(\d+\.\d+\.\d+).*', p.stdout)
                if m:
                    self._caddy_version = m.group(1)
                else:
                    raise RuntimeError(f'Unable to determine cadd version from: {p.stdout}')
            # TODO: specify specific exceptions here
            except:  # noqa: E722
                self.caddy = None

        self.vsftpd = self.config['vsftpd']['vsftpd']
        if self.vsftpd == '':
            self.vsftpd = None
        self._vsftpd_version = None
        if self.vsftpd is not None:
            try:
                with tempfile.TemporaryFile('w+') as tmp:
                    p = subprocess.run(args=[self.vsftpd, '-v'],
                                       capture_output=True, text=True, stdin=tmp)
                    if p.returncode != 0:
                        # not a working vsftpd
                        self.vsftpd = None
                    if p.stderr:
                        ver_text = p.stderr
                    else:
                        # Oddly, some versions of vsftpd write to stdin (!)
                        # instead of stderr, which is odd but works. If there
                        # is nothing on stderr, read the file on stdin and use
                        # any data there instead.
                        tmp.seek(0)
                        ver_text = tmp.read()
                m = re.match(r'vsftpd: version (\d+\.\d+\.\d+)', ver_text)
                if m:
                    self._vsftpd_version = m.group(1)
                elif len(p.stderr) == 0:
                    # vsftp does not use stdout or stderr for printing its version... -.-
                    self._vsftpd_version = 'unknown'
                else:
                    raise Exception(f'Unable to determine VsFTPD version from: {p.stderr}')
            except Exception:
                self.vsftpd = None

        self.danted = self.config['danted']['danted']
        if self.danted == '':
            self.danted = None
        self._danted_version = None
        if self.danted is not None:
            try:
                p = subprocess.run(args=[self.danted, '-v'],
                                   capture_output=True, text=True)
                assert p.returncode == 0
                if p.returncode != 0:
                    # not a working vsftpd
                    self.danted = None
                m = re.match(r'^Dante v(\d+\.\d+\.\d+).*', p.stdout)
                if not m:
                    m = re.match(r'^Dante v(\d+\.\d+\.\d+).*', p.stderr)
                if m:
                    self._danted_version = m.group(1)
                else:
                    self.danted = None
                    raise Exception(f'Unable to determine danted version from: {p.stderr}')
            except Exception:
                self.danted = None

        self._tcpdump = shutil.which('tcpdump')

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
            except Exception:
                log.exception(f'{self.apxs} failed to run')
        return self._httpd_version

    def versiontuple(self, v):
        v = re.sub(r'(\d+\.\d+(\.\d+)?)(-\S+)?', r'\1', v)
        return tuple(map(int, v.split('.')))

    def httpd_is_at_least(self, minv):
        if self.httpd_version is None:
            return False
        hv = self.versiontuple(self.httpd_version)
        return hv >= self.versiontuple(minv)

    def caddy_is_at_least(self, minv):
        if self.caddy_version is None:
            return False
        hv = self.versiontuple(self.caddy_version)
        return hv >= self.versiontuple(minv)

    def is_complete(self) -> bool:
        return os.path.isfile(self.httpd) and \
               self.apxs is not None and \
               os.path.isfile(self.apxs)

    def get_incomplete_reason(self) -> Optional[str]:
        if self.httpd is None or len(self.httpd.strip()) == 0:
            return 'httpd not configured, see `--with-test-httpd=<path>`'
        if not os.path.isfile(self.httpd):
            return f'httpd ({self.httpd}) not found'
        if self.apxs is None:
            return "command apxs not found (commonly provided in apache2-dev)"
        if not os.path.isfile(self.apxs):
            return f"apxs ({self.apxs}) not found"
        return None

    @property
    def nghttpx_version(self):
        return self._nghttpx_version

    @property
    def caddy_version(self):
        return self._caddy_version

    @property
    def vsftpd_version(self):
        return self._vsftpd_version

    @property
    def tcpdmp(self) -> Optional[str]:
        return self._tcpdump

    def clear_locks(self):
        ca_lock = os.path.join(self.gen_root, 'ca/ca.lock')
        if os.path.exists(ca_lock):
            os.remove(ca_lock)


class Env:

    SERVER_TIMEOUT = 30  # seconds to wait for server to come up/reload

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
        return Env.curl_has_feature('ssl') or Env.curl_has_feature('multissl')

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
    def curl_uses_any_libs(libs: List[str]) -> bool:
        for libname in libs:
            if libname.lower() in Env.CONFIG.curl_props['libs']:
                return True
        return False

    @staticmethod
    def curl_uses_ossl_quic() -> bool:
        if Env.have_h3_curl():
            return not Env.curl_uses_lib('ngtcp2') and Env.curl_uses_lib('nghttp3')
        return False

    @staticmethod
    def curl_version_string() -> str:
        return Env.CONFIG.curl_props['version_string']

    @staticmethod
    def curl_features_string() -> str:
        return Env.CONFIG.curl_props['features_string']

    @staticmethod
    def curl_has_feature(feature: str) -> bool:
        return feature.lower() in Env.CONFIG.curl_props['features']

    @staticmethod
    def curl_protocols_string() -> str:
        return Env.CONFIG.curl_props['protocols_string']

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
    def curl_lib_version_at_least(libname: str, min_version) -> bool:
        lversion = Env.curl_lib_version(libname)
        if lversion != 'unknown':
            return Env.CONFIG.versiontuple(min_version) <= \
                   Env.CONFIG.versiontuple(lversion)
        return False

    @staticmethod
    def curl_lib_version_before(libname: str, lib_version) -> bool:
        lversion = Env.curl_lib_version(libname)
        if lversion != 'unknown':
            if m := re.match(r'(\d+\.\d+\.\d+).*', lversion):
                lversion = m.group(1)
            return Env.CONFIG.versiontuple(lib_version) > \
                Env.CONFIG.versiontuple(lversion)
        return False

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
    def curl_is_debug() -> bool:
        return Env.CONFIG.curl_is_debug

    @staticmethod
    def curl_can_early_data() -> bool:
        if Env.curl_uses_lib('gnutls'):
            return Env.curl_lib_version_at_least('gnutls', '3.6.13')
        return Env.curl_uses_any_libs(['wolfssl', 'quictls', 'openssl'])

    @staticmethod
    def curl_can_h3_early_data() -> bool:
        return Env.curl_can_early_data() and \
            Env.curl_uses_lib('ngtcp2')

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
    def caddy_is_at_least(minv) -> bool:
        return Env.CONFIG.caddy_is_at_least(minv)

    @staticmethod
    def httpd_is_at_least(minv) -> bool:
        return Env.CONFIG.httpd_is_at_least(minv)

    @staticmethod
    def has_caddy() -> bool:
        return Env.CONFIG.caddy is not None

    @staticmethod
    def has_vsftpd() -> bool:
        return Env.CONFIG.vsftpd is not None

    @staticmethod
    def vsftpd_version() -> str:
        return Env.CONFIG.vsftpd_version

    @staticmethod
    def has_danted() -> bool:
        return Env.CONFIG.danted is not None

    @staticmethod
    def tcpdump() -> Optional[str]:
        return Env.CONFIG.tcpdmp

    def __init__(self, pytestconfig=None, env_config=None):
        if env_config:
            Env.CONFIG = env_config
        self._verbose = pytestconfig.option.verbose \
            if pytestconfig is not None else 0
        self._ca = None
        self._test_timeout = 300.0 if self._verbose > 1 else 60.0  # seconds

    def issue_certs(self):
        if self._ca is None:
            ca_dir = os.path.join(self.CONFIG.gen_root, 'ca')
            os.makedirs(ca_dir, exist_ok=True)
            lock_file = os.path.join(ca_dir, 'ca.lock')
            with FileLock(lock_file):
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
    def gen_root(self) -> str:
        return self.CONFIG.gen_root

    @property
    def project_dir(self) -> str:
        return self.CONFIG.project_dir

    @property
    def build_dir(self) -> str:
        return self.CONFIG.build_dir

    @property
    def ca(self):
        return self._ca

    @property
    def htdocs_dir(self) -> str:
        return self.CONFIG.htdocs_dir

    @property
    def tld(self) -> str:
        return self.CONFIG.tld

    @property
    def domain1(self) -> str:
        return self.CONFIG.domain1

    @property
    def domain1brotli(self) -> str:
        return self.CONFIG.domain1brotli

    @property
    def domain2(self) -> str:
        return self.CONFIG.domain2

    @property
    def ftp_domain(self) -> str:
        return self.CONFIG.ftp_domain

    @property
    def proxy_domain(self) -> str:
        return self.CONFIG.proxy_domain

    @property
    def expired_domain(self) -> str:
        return self.CONFIG.expired_domain

    @property
    def ports(self) -> Dict[str, int]:
        return self.CONFIG.ports

    def update_ports(self, ports: Dict[str, int]):
        self.CONFIG.ports.update(ports)

    @property
    def http_port(self) -> int:
        return self.CONFIG.ports.get('http', 0)

    @property
    def https_port(self) -> int:
        return self.CONFIG.ports['https']

    @property
    def https_only_tcp_port(self) -> int:
        return self.CONFIG.ports['https-tcp-only']

    @property
    def nghttpx_https_port(self) -> int:
        return self.CONFIG.ports['nghttpx_https']

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
    def ftp_port(self) -> int:
        return self.CONFIG.ports['ftp']

    @property
    def ftps_port(self) -> int:
        return self.CONFIG.ports['ftps']

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
    def danted(self) -> str:
        return self.CONFIG.danted

    @property
    def vsftpd(self) -> str:
        return self.CONFIG.vsftpd

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
    def apxs(self) -> str:
        return self.CONFIG.apxs

    @property
    def nghttpx(self) -> Optional[str]:
        return self.CONFIG.nghttpx

    @property
    def slow_network(self) -> bool:
        return "CURL_DBG_SOCK_WBLOCK" in os.environ or \
               "CURL_DBG_SOCK_WPARTIAL" in os.environ

    @property
    def ci_run(self) -> bool:
        return "CURL_CI" in os.environ

    def port_for(self, alpn_proto: Optional[str] = None):
        if alpn_proto is None or \
                alpn_proto in ['h2', 'http/1.1', 'http/1.0', 'http/0.9']:
            return self.https_port
        if alpn_proto in ['h3']:
            return self.h3_port
        return self.http_port

    def authority_for(self, domain: str, alpn_proto: Optional[str] = None):
        return f'{domain}:{self.port_for(alpn_proto=alpn_proto)}'

    def make_data_file(self, indir: str, fname: str, fsize: int,
                       line_length: int = 1024) -> str:
        if line_length < 11:
            raise RuntimeError('line_length less than 11 not supported')
        fpath = os.path.join(indir, fname)
        s10 = "0123456789"
        s = round((line_length / 10) + 1) * s10
        s = s[0:line_length-11]
        with open(fpath, 'w') as fd:
            for i in range(int(fsize / line_length)):
                fd.write(f"{i:09d}-{s}\n")
            remain = int(fsize % line_length)
            if remain != 0:
                i = int(fsize / line_length) + 1
                fd.write(f"{i:09d}-{s}"[0:remain-1] + "\n")
        return fpath

    def make_data_gzipbomb(self, indir: str, fname: str, fsize: int) -> str:
        fpath = os.path.join(indir, fname)
        gzpath = f'{fpath}.gz'
        varpath = f'{fpath}.var'

        with open(fpath, 'w') as fd:
            fd.write('not what we are looking for!\n')
        count = int(fsize / 1024)
        zero1k = bytearray(1024)
        with gzip.open(gzpath, 'wb') as fd:
            for _ in range(count):
                fd.write(zero1k)
        with open(varpath, 'w') as fd:
            fd.write(f'URI: {fname}\n')
            fd.write('\n')
            fd.write(f'URI: {fname}.gz\n')
            fd.write('Content-Type: text/plain\n')
            fd.write('Content-Encoding: x-gzip\n')
            fd.write('\n')
        return fpath
