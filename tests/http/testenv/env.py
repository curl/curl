# ***************************************************************************
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
import string
import subprocess
import tempfile
from configparser import ConfigParser, ExtendedInterpolation
from datetime import timedelta
from typing import Dict, List, Optional

import pytest
from filelock import FileLock

from .certs import CertificateSpec, Credentials, TestCA

log = logging.getLogger(__name__)


class EnvError(Exception):
    """Exception from the test environment."""


def init_config_from(conf_path):
    if os.path.isfile(conf_path):
        config = ConfigParser(interpolation=ExtendedInterpolation())
        config.read(conf_path)
        return config
    return None


TESTS_HTTPD_PATH = os.path.dirname(os.path.dirname(__file__))
PROJ_PATH = os.path.dirname(os.path.dirname(TESTS_HTTPD_PATH))
TOP_PATH = os.path.join(os.getcwd(), os.path.pardir)
CONFIG_PATH = os.path.join(TOP_PATH, "tests", "http", "config.ini")
if not os.path.exists(CONFIG_PATH):
    ALT_CONFIG_PATH = os.path.join(PROJ_PATH, "tests", "http", "config.ini")
    if not os.path.exists(ALT_CONFIG_PATH):
        raise EnvError(
            f"unable to find config.ini in {CONFIG_PATH} nor {ALT_CONFIG_PATH}"
        )
    TOP_PATH = PROJ_PATH
    CONFIG_PATH = ALT_CONFIG_PATH
DEF_CONFIG = init_config_from(CONFIG_PATH)
CURL = os.path.join(TOP_PATH, "src", "curl")
CURLINFO = os.path.join(TOP_PATH, "src", "curlinfo")


class NghttpxUtil:
    CMD = None
    VERSION_FULL = None
    CAN_ECH = None

    @classmethod
    def version(cls, cmd):
        if cmd is None:
            return None
        if cls.VERSION_FULL is None or cmd != cls.CMD:
            p = subprocess.run(args=[cmd, "--version"], capture_output=True, text=True, check=True)
            cls.CMD = cmd
            for line in p.stdout.splitlines(keepends=False):
                if line.startswith("nghttpx "):
                    cls.VERSION_FULL = line
            if cls.VERSION_FULL is None:
                raise RuntimeError(f"{cmd}: unable to determine version")
        return cls.VERSION_FULL

    @staticmethod
    def version_with_h3(version):
        return re.match(r".* ngtcp2/\d+\.\d+\.\d+.*", version) is not None

    @classmethod
    def can_ech(cls, cmd):
        if cmd is None:
            return None
        if cls.CAN_ECH is None or cmd != cls.CMD:
            p = subprocess.run(args=[cmd, "-h"], capture_output=True, text=True, check=True)
            cls.CMD = cmd
            cls.CAN_ECH = False
            for line in p.stdout.splitlines(keepends=False):
                if re.search(r'--ech-config-file', line):
                    cls.CAN_ECH = True
                    break
        return cls.CAN_ECH


class EnvConfig:
    def __init__(
        self,
        pytestconfig: Optional[pytest.Config] = None,
        testrun_uid=None,
        worker_id=None,
    ):
        self.pytestconfig = pytestconfig
        self.testrun_uid = testrun_uid
        self.worker_id = worker_id if worker_id is not None else "master"
        self.tests_dir = TESTS_HTTPD_PATH
        self.gen_root = self.gen_dir = os.path.join(self.tests_dir, "gen")
        if self.worker_id != "master":
            self.gen_dir = os.path.join(self.gen_dir, self.worker_id)
        self.project_dir = os.path.dirname(os.path.dirname(self.tests_dir))
        self.build_dir = TOP_PATH
        self.config = DEF_CONFIG
        # check cur and its features
        self.curl = CURL
        self.curlinfo = CURLINFO
        if "CURL" in os.environ:
            self.curl = os.environ["CURL"]
        self.curl_props = {
            "version_string": "",
            "version": "",
            "os": "",
            "fullname": "",
            "features_string": "",
            "features": set(),
            "protocols_string": "",
            "protocols": set(),
            "libs": set(),
            "lib_versions": set(),
        }
        self.curl_is_debug = False
        self.curl_protos = []
        p = subprocess.run(args=[self.curl, "-V"], capture_output=True, text=True, check=True)
        if p.stderr.startswith("WARNING:"):
            self.curl_is_debug = True
        for line in p.stdout.splitlines(keepends=False):
            if line.startswith("curl "):
                self.curl_props["version_string"] = line
                m = re.match(r"^curl (?P<version>\S+) (?P<os>\S+) (?P<libs>.*)$", line)
                if m:
                    self.curl_props["fullname"] = m.group(0)
                    self.curl_props["version"] = m.group("version")
                    self.curl_props["os"] = m.group("os")
                    self.curl_props["lib_versions"] = {
                        lib.lower() for lib in m.group("libs").split(" ")
                    }
                    self.curl_props["libs"] = {
                        re.sub(r"/[a-z0-9.-]*", "", lib)
                        for lib in self.curl_props["lib_versions"]
                    }
            if line.startswith("Features: "):
                self.curl_props["features_string"] = line[10:]
                self.curl_props["features"] = {
                    feat.lower() for feat in line[10:].split(" ")
                }
            if line.startswith("Protocols: "):
                self.curl_props["protocols_string"] = line[11:]
                self.curl_props["protocols"] = {
                    prot.lower() for prot in line[11:].split(" ")
                }

        p = subprocess.run(args=[self.curlinfo], capture_output=True, text=True, check=True)
        self.curl_is_verbose = 'verbose-strings: ON' in p.stdout
        self.curl_can_cert_status = 'cert-status: ON' in p.stdout
        self.curl_override_dns = 'override-dns: ON' in p.stdout
        self.curl_resolv_threaded = 'resolv-threaded: ON' in p.stdout
        self.curl_can_doh = 'DoH: ON' in p.stdout

        self.ports = {}

        self.httpd = self.config["httpd"]["httpd"]
        self.apxs = self.config["httpd"]["apxs"]
        if len(self.apxs) == 0:
            self.apxs = None
        self._httpd_version = None

        self.examples_pem = {
            "key": "xxx",
            "cert": "xxx",
        }
        self.htdocs_dir = os.path.join(self.gen_dir, "htdocs")
        self.tld = "http.curl.se"
        self.domain1 = f"one.{self.tld}"
        self.domain1brotli = f"brotli.one.{self.tld}"
        self.domain2 = f"two.{self.tld}"
        self.ftp_domain = f"ftp.{self.tld}"
        self.proxy_domain = f"proxy.{self.tld}"
        self.expired_domain = f"expired.{self.tld}"
        self.cert_specs = [
            CertificateSpec(
                domains=[self.domain1, self.domain1brotli, "localhost", "127.0.0.1"],
                key_type="rsa2048",
            ),
            CertificateSpec(
                name="domain1-no-ip",
                domains=[self.domain1, self.domain1brotli],
                key_type="rsa2048",
            ),
            CertificateSpec(
                name="domain1-very-bad",
                domains=[self.domain1, "dns:127.0.0.1"],
                key_type="rsa2048",
            ),
            CertificateSpec(domains=[self.domain2], key_type="rsa2048"),
            CertificateSpec(domains=[self.ftp_domain], key_type="rsa2048"),
            CertificateSpec(
                domains=[self.proxy_domain, "127.0.0.1"], key_type="rsa2048"
            ),
            CertificateSpec(
                domains=[self.expired_domain],
                key_type="rsa2048",
                valid_from=timedelta(days=-100),
                valid_to=timedelta(days=-10),
            ),
            CertificateSpec(
                name="clientsX",
                sub_specs=[
                    CertificateSpec(name="user1", client=True),
                ],
            ),
            CertificateSpec(
                name='embedded-zero',
                domains=[f'{self.domain1}\0actually.{self.domain2}'],
                key_type='rsa2048',
            ),
            CertificateSpec(
                name='embedded-zero-wildcard',
                domains=[f'*.{self.tld}\0actually.{self.domain2}'],
                key_type='rsa2048',
            ),
        ]

        if "OPENSSL" in os.environ:
            self.openssl = os.environ["OPENSSL"]
        else:
            self.openssl = "openssl"
        self.openssl_ech = False
        p = subprocess.run(
            args=[self.openssl, "version"], capture_output=True, text=True, check=False
        )
        if p.returncode != 0:
            # no openssl in path
            self.openssl = None
            self.openssl_version = None
        else:
            self.openssl_version = p.stdout.strip()
            m = re.match(r'OpenSSL (\d+).*', self.openssl_version)
            if m and int(m.group(1)) >= 4:
                self.openssl_ech = True

        self.nghttpx = self.config["nghttpx"]["nghttpx"]
        if len(self.nghttpx.strip()) == 0:
            self.nghttpx = None
        self.nghttpx_ech = False
        self._nghttpx_version = None
        self.nghttpx_with_h3 = False
        if self.nghttpx is not None:
            self._nghttpx_version = NghttpxUtil.version(self.nghttpx)
            self.nghttpx_with_h3 = NghttpxUtil.version_with_h3(self._nghttpx_version)
            self.nghttpx_ech = NghttpxUtil.can_ech(self.nghttpx)

        self.caddy = self.config["caddy"]["caddy"]
        self._caddy_version = None
        if len(self.caddy.strip()) == 0:
            self.caddy = None

        self.h2o = self.config["h2o"]["h2o"]
        if len(self.h2o.strip()) == 0:
            self.h2o = None
        self._h2o_version = None
        if self.h2o is not None:
            try:
                p = subprocess.run(
                    args=[self.h2o, "--version"], capture_output=True, text=True, check=False
                )
                if p.returncode != 0:
                    # not a working h2o
                    self.h2o = None
                else:
                    # h2o --version output format: "h2o version 2.3.0"
                    m = re.search(r"h2o version (\S+)", p.stdout)
                    if m:
                        self._h2o_version = m.group(1)
                    else:
                        self.h2o = None
            except Exception:
                log.exception("checking h2o version")
                self.h2o = None

        if self.caddy is not None:
            p = subprocess.run(
                args=[self.caddy, "version"], capture_output=True, text=True, check=False
            )
            if p.returncode != 0:
                # not a working caddy
                self.caddy = None
            m = re.match(r"v?(\d+\.\d+\.\d+).*", p.stdout)
            if m:
                self._caddy_version = m.group(1)
            else:
                raise RuntimeError(
                    f"Unable to determine caddy version from: {p.stdout}"
                )

        self.vsftpd = self.config["vsftpd"]["vsftpd"]
        if self.vsftpd == "":
            self.vsftpd = None
        self._vsftpd_version = None
        if self.vsftpd is not None:
            with tempfile.TemporaryFile("w+") as tmp:
                p = subprocess.run(
                    args=[self.vsftpd, "-v"], capture_output=True, text=True, stdin=tmp, check=False
                )
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
            m = re.match(r"vsftpd: version (\d+\.\d+\.\d+)", ver_text)
            if m:
                self._vsftpd_version = m.group(1)
            elif len(p.stderr) == 0:
                # vsftp does not use stdout or stderr for printing its version... -.-
                self._vsftpd_version = "unknown"
            else:
                raise EnvError(f"Unable to determine VsFTPD version from: {p.stderr}")

        self.danted = self.config["danted"]["danted"]
        if self.danted == "":
            self.danted = None
        self._danted_version = None
        if self.danted is not None:
            p = subprocess.run(args=[self.danted, "-v"], capture_output=True, text=True, check=False)
            assert p.returncode == 0
            if p.returncode != 0:
                # not a working vsftpd
                self.danted = None
            m = re.match(r"^Dante v(\d+\.\d+\.\d+).*", p.stdout)
            if not m:
                m = re.match(r"^Dante v(\d+\.\d+\.\d+).*", p.stderr)
            if m:
                self._danted_version = m.group(1)
            else:
                self.danted = None
                raise EnvError(f"Unable to determine danted version from: {p.stderr}")

        self.sshd = self.config["sshd"]["sshd"]
        if self.sshd == "":
            self.sshd = None
        self._sshd_version = None
        if self.sshd is not None:
            p = subprocess.run(args=[self.sshd, "-V"], capture_output=True, text=True, check=False)
            assert p.returncode == 0
            if p.returncode != 0:
                self.sshd = None
            else:
                m = re.match(r"^OpenSSH_(\d+\.\d+.*),.*", p.stderr)
                assert m, f"version: {p.stderr}"
                if m:
                    self._sshd_version = m.group(1)
                else:
                    self.sshd = None
                    raise EnvError(
                        f"Unable to determine sshd version from: {p.stderr}"
                    )

        if self.sshd:
            self.sftpd = self.config["sshd"]["sftpd"]
            if self.sftpd == "":
                self.sftpd = None
        else:
            self.sftpd = None

        self._tcpdump = shutil.which("tcpdump")

    @property
    def httpd_version(self):
        if self._httpd_version is None and self.apxs is not None:
            try:
                p = subprocess.run(
                    args=[self.apxs, "-q", "HTTPD_VERSION"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if p.returncode != 0:
                    log.error(f"{self.apxs} failed to query HTTPD_VERSION: {p}")
                else:
                    self._httpd_version = p.stdout.strip()
            except Exception:
                log.exception(f"{self.apxs} failed to run")
        return self._httpd_version

    def versiontuple(self, v):
        v = re.sub(r"(\d+\.\d+(\.\d+)?)(-\S+)?", r"\1", v)
        return tuple(map(int, v.split(".")))

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
        return (
            os.path.isfile(self.httpd)
            and self.apxs is not None
            and os.path.isfile(self.apxs)
        )

    def get_incomplete_reason(self) -> Optional[str]:
        if self.httpd is None or len(self.httpd.strip()) == 0:
            return "httpd not configured, see `--with-test-httpd=<path>`"
        if not os.path.isfile(self.httpd):
            return f"httpd ({self.httpd}) not found"
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
    def h2o_version(self):
        return self._h2o_version

    @property
    def tcpdump(self) -> Optional[str]:
        return self._tcpdump

    def clear_locks(self):
        ca_lock = os.path.join(self.gen_root, "ca/ca.lock")
        if os.path.exists(ca_lock):
            os.remove(ca_lock)


class Env:
    SERVER_TIMEOUT = 30  # seconds to wait for server to come up/reload

    CONFIG = EnvConfig()

    @classmethod
    def setup_incomplete(cls) -> bool:
        return not cls.CONFIG.is_complete()

    @classmethod
    def incomplete_reason(cls) -> Optional[str]:
        return cls.CONFIG.get_incomplete_reason()

    @classmethod
    def have_openssl(cls) -> bool:
        return cls.CONFIG.openssl is not None

    @classmethod
    def have_nghttpx(cls) -> bool:
        return cls.CONFIG.nghttpx is not None

    @classmethod
    def have_h3_server(cls) -> bool:
        return cls.CONFIG.nghttpx_with_h3

    @staticmethod
    def have_openssl_ech() -> bool:
        return Env.CONFIG.openssl_ech

    @staticmethod
    def have_nghttpx_ech() -> bool:
        return Env.CONFIG.nghttpx_ech

    @classmethod
    def have_h2o(cls) -> bool:
        return cls.CONFIG.h2o is not None

    @classmethod
    def have_ssl_curl(cls) -> bool:
        return cls.curl_has_feature("ssl") or cls.curl_has_feature("multissl")

    @classmethod
    def have_h2_curl(cls) -> bool:
        return "http2" in cls.CONFIG.curl_props["features"]

    @classmethod
    def have_h3_curl(cls) -> bool:
        return "http3" in cls.CONFIG.curl_props["features"]

    @classmethod
    def have_compressed_curl(cls) -> bool:
        return (
            "brotli" in cls.CONFIG.curl_props["libs"]
            or "zlib" in cls.CONFIG.curl_props["libs"]
            or "zstd" in cls.CONFIG.curl_props["libs"]
        )

    @classmethod
    def curl_uses_lib(cls, libname: str) -> bool:
        return libname.lower() in cls.CONFIG.curl_props["libs"]

    @classmethod
    def curl_uses_any_libs(cls, libs: List[str]) -> bool:
        return any(libname.lower() in cls.CONFIG.curl_props["libs"] for libname in libs)

    @classmethod
    def curl_uses_ossl_quic(cls) -> bool:
        if cls.have_h3_curl():
            return not cls.curl_uses_lib("ngtcp2") and cls.curl_uses_lib("nghttp3")
        return False

    @classmethod
    def curl_version_string(cls) -> str:
        return cls.CONFIG.curl_props["version_string"]

    @classmethod
    def curl_version_at_least(cls, min_version) -> bool:
        version = cls.curl_version()
        return cls.CONFIG.versiontuple(min_version) <= cls.CONFIG.versiontuple(
            version
        )

    @classmethod
    def curl_features_string(cls) -> str:
        return cls.CONFIG.curl_props["features_string"]

    @classmethod
    def curl_has_feature(cls, feature: str) -> bool:
        return feature.lower() in cls.CONFIG.curl_props["features"]

    @classmethod
    def curl_protocols_string(cls) -> str:
        return cls.CONFIG.curl_props["protocols_string"]

    @classmethod
    def curl_has_protocol(cls, protocol: str) -> bool:
        return protocol.lower() in cls.CONFIG.curl_props["protocols"]

    @classmethod
    def curl_lib_version(cls, libname: str) -> str:
        prefix = f"{libname.lower()}/"
        for lversion in cls.CONFIG.curl_props["lib_versions"]:
            if lversion.startswith(prefix):
                return lversion[len(prefix):]
        return "unknown"

    @classmethod
    def curl_lib_version_at_least(cls, libname: str, min_version) -> bool:
        lversion = cls.curl_lib_version(libname)
        if lversion != "unknown":
            return cls.CONFIG.versiontuple(min_version) <= cls.CONFIG.versiontuple(
                lversion
            )
        return False

    @classmethod
    def curl_lib_version_before(cls, libname: str, lib_version) -> bool:
        lversion = cls.curl_lib_version(libname)
        if lversion != "unknown":
            if m := re.match(r"(\d+\.\d+\.\d+).*", lversion):
                lversion = m.group(1)
            return cls.CONFIG.versiontuple(lib_version) > cls.CONFIG.versiontuple(
                lversion
            )
        return False

    @classmethod
    def curl_os(cls) -> str:
        return cls.CONFIG.curl_props["os"]

    @classmethod
    def curl_fullname(cls) -> str:
        return cls.CONFIG.curl_props["fullname"]

    @classmethod
    def curl_version(cls) -> str:
        return cls.CONFIG.curl_props["version"]

    @classmethod
    def curl_is_debug(cls) -> bool:
        return cls.CONFIG.curl_is_debug

    @classmethod
    def curl_is_verbose(cls) -> bool:
        return cls.CONFIG.curl_is_verbose

    @classmethod
    def curl_can_cert_status(cls) -> bool:
        return cls.CONFIG.curl_can_cert_status

    @classmethod
    def curl_override_dns(cls) -> bool:
        return cls.CONFIG.curl_override_dns

    @classmethod
    def curl_resolv_threaded(cls) -> bool:
        return cls.CONFIG.curl_resolv_threaded

    @classmethod
    def curl_can_doh(cls) -> bool:
        return cls.CONFIG.curl_can_doh

    @classmethod
    def curl_can_early_data(cls) -> bool:
        if cls.curl_uses_lib('gnutls'):
            return cls.curl_lib_version_at_least('gnutls', '3.7.2')
        return cls.curl_uses_any_libs(['wolfssl', 'quictls', 'openssl'])

    @classmethod
    def curl_can_h3_early_data(cls) -> bool:
        return cls.curl_can_early_data() and cls.curl_uses_lib("ngtcp2")

    @classmethod
    def http_protos(cls) -> List[str]:
        # http protocols we can test
        if cls.have_h2_curl():
            if cls.have_h3():
                return ["http/1.1", "h2", "h3"]
            return ["http/1.1", "h2"]
        return ["http/1.1"]

    @classmethod
    def http_h1_h2_protos(cls) -> List[str]:
        # http 1+2 protocols we can test
        if cls.have_h2_curl():
            return ["http/1.1", "h2"]
        return ["http/1.1"]

    @classmethod
    def http_mplx_protos(cls) -> List[str]:
        # http multiplexing protocols we can test
        if cls.have_h2_curl():
            if cls.have_h3():
                return ["h2", "h3"]
            return ["h2"]
        return []

    @classmethod
    def have_h3(cls) -> bool:
        return cls.have_h3_curl() and cls.have_h3_server()

    @classmethod
    def httpd_version(cls) -> str:
        return cls.CONFIG.httpd_version

    @classmethod
    def nghttpx_version(cls) -> str:
        return cls.CONFIG.nghttpx_version

    @classmethod
    def caddy_version(cls) -> str:
        return cls.CONFIG.caddy_version

    @classmethod
    def h2o_version(cls) -> str:
        return cls.CONFIG.h2o_version

    @classmethod
    def caddy_is_at_least(cls, minv) -> bool:
        return cls.CONFIG.caddy_is_at_least(minv)

    @classmethod
    def httpd_is_at_least(cls, minv) -> bool:
        return cls.CONFIG.httpd_is_at_least(minv)

    @classmethod
    def has_caddy(cls) -> bool:
        return cls.CONFIG.caddy is not None

    @classmethod
    def has_vsftpd(cls) -> bool:
        return cls.CONFIG.vsftpd is not None

    @classmethod
    def vsftpd_version(cls) -> str:
        return cls.CONFIG.vsftpd_version

    @classmethod
    def has_danted(cls) -> bool:
        return cls.CONFIG.danted is not None

    @classmethod
    def has_sshd(cls) -> bool:
        return cls.CONFIG.sshd is not None

    @classmethod
    def has_sftpd(cls) -> bool:
        return cls.has_sshd() and cls.CONFIG.sftpd is not None

    @classmethod
    def tcpdump(cls) -> Optional[str]:
        return cls.CONFIG.tcpdump

    def __init__(self, pytestconfig=None, env_config=None):
        if env_config:
            Env.CONFIG = env_config
        self._verbose = pytestconfig.option.verbose if pytestconfig is not None else 0
        self._ca = None
        self._test_timeout = 300.0 if self._verbose > 1 else 60.0  # seconds

    def issue_certs(self):
        if self._ca is None:
            # ca_dir = os.path.join(self.CONFIG.gen_root, 'ca')
            ca_dir = os.path.join(self.gen_dir, "ca")
            os.makedirs(ca_dir, exist_ok=True)
            lock_file = os.path.join(ca_dir, "ca.lock")
            with FileLock(lock_file):
                self._ca = TestCA.create_root(
                    name=self.CONFIG.tld, store_dir=ca_dir, key_type="rsa2048"
                )
                self._ca.issue_certs(self.CONFIG.cert_specs)
                if self.have_openssl():
                    self._ca.create_hashdir(self.openssl)
                if self.have_openssl_ech():
                    for domain in [self.domain1, self.domain2]:
                        p = subprocess.run(args=[
                            self.openssl, 'ech',
                            '-out', os.path.join(ca_dir, f'{domain}.echconfig'),
                            '-public_name', f'public.{domain}'
                        ], capture_output=True, text=True, check=True)
                        if p.returncode != 0:
                            raise EnvError(f"Error generating ECHConfig for {domain}")

    def setup(self):
        os.makedirs(self.gen_dir, exist_ok=True)
        os.makedirs(self.htdocs_dir, exist_ok=True)
        self.issue_certs()

    def get_credentials(self, domain) -> Optional[Credentials]:
        creds = self.ca.get_credentials_for_name(domain)
        if len(creds) > 0:
            return creds[0]
        return None

    def get_echconfig_file(self, domain) -> Optional[str]:
        ech_file = os.path.join(self.gen_dir, f"ca/{domain}.echconfig")
        if os.path.exists(ech_file):
            return ech_file
        return None

    def get_echconfig_arg(self, domain) -> Optional[str]:
        ech_file = self.get_echconfig_file(domain)
        if ech_file:
            ech_config = ''
            in_pem = False
            with open(ech_file) as fd:
                for line in fd.read().splitlines():
                    if not in_pem and line == '-----BEGIN ECHCONFIG-----':
                        in_pem = True
                    elif in_pem and line == '-----END ECHCONFIG-----':
                        break
                    elif in_pem:
                        ech_config += line
            return ech_config
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
        return self.CONFIG.ports.get("http", 0)

    @property
    def https_port(self) -> int:
        return self.CONFIG.ports["https"]

    @property
    def https_only_tcp_port(self) -> int:
        return self.CONFIG.ports["https-tcp-only"]

    @property
    def nghttpx_https_port(self) -> int:
        return self.CONFIG.ports["nghttpx_https"]

    @property
    def h3_port(self) -> int:
        return self.https_port

    @property
    def proxy_port(self) -> int:
        return self.CONFIG.ports["proxy"]

    @property
    def proxys_port(self) -> int:
        return self.CONFIG.ports["proxys"]

    @property
    def ftp_port(self) -> int:
        return self.CONFIG.ports["ftp"]

    @property
    def ftps_port(self) -> int:
        return self.CONFIG.ports["ftps"]

    @property
    def h2proxys_port(self) -> int:
        return self.CONFIG.ports["h2proxys"]

    @property
    def h3proxys_port(self) -> int:
        return self.CONFIG.ports["h2o_h3proxys"]

    def pts_port(self, proto: str = "http/1.1", use_h2o: bool = False) -> int:
        # proxy tunnel port
        prefix = 'h2o_' if use_h2o else ''
        if proto == "h3":
            return self.CONFIG.ports.get("h2o_h3proxys", 0)
        if proto == "h2":
            return self.CONFIG.ports.get(f"{prefix}h2proxys", 0)
        return self.CONFIG.ports[f"{prefix}proxys"]

    @property
    def caddy(self) -> str:
        return self.CONFIG.caddy

    @property
    def caddy_https_port(self) -> int:
        return self.CONFIG.ports["caddys"]

    @property
    def caddy_http_port(self) -> int:
        return self.CONFIG.ports["caddy"]

    @property
    def danted(self) -> str:
        return self.CONFIG.danted

    @property
    def vsftpd(self) -> str:
        return self.CONFIG.vsftpd

    @property
    def curl(self) -> str:
        return self.CONFIG.curl

    @property
    def openssl(self) -> Optional[str]:
        return self.CONFIG.openssl

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
        return (
            "CURL_DBG_SOCK_WBLOCK" in os.environ
            or "CURL_DBG_SOCK_WPARTIAL" in os.environ
        )

    @property
    def ci_run(self) -> bool:
        return "CURL_CI" in os.environ

    def port_for(self, alpn_proto: Optional[str] = None):
        if alpn_proto is None or alpn_proto in [
            "h2",
            "http/1.1",
            "http/1.0",
            "http/0.9",
        ]:
            return self.https_port
        if alpn_proto == "h3":
            return self.h3_port
        return self.http_port

    def authority_for(self, domain: str, alpn_proto: Optional[str] = None):
        return f"{domain}:{self.port_for(alpn_proto=alpn_proto)}"

    def make_data_file(
        self, indir: str, fname: str, fsize: int, line_length: int = 1024
    ) -> str:
        if line_length < 11:
            raise RuntimeError("line_length less than 11 not supported")
        os.makedirs(indir, exist_ok=True)
        fpath = os.path.join(indir, fname)
        s10 = string.digits
        s = round((line_length / 10) + 1) * s10
        s = s[0:line_length - 11]
        with open(fpath, "w") as fd:
            fd.writelines(f"{i:09d}-{s}\n" for i in range(int(fsize / line_length)))
            remain = int(fsize % line_length)
            if remain != 0:
                i = int(fsize / line_length) + 1
                fd.write(f"{i:09d}-{s}"[0:remain - 1] + "\n")
        return fpath

    def make_data_gzipbomb(self, indir: str, fname: str, fsize: int) -> str:
        fpath = os.path.join(indir, fname)
        gzpath = f"{fpath}.gz"
        varpath = f"{fpath}.var"

        with open(fpath, "w") as fd:
            fd.write("not what we are looking for!\n")
        count = int(fsize / 1024)
        zero1k = bytearray(1024)
        with gzip.open(gzpath, "wb") as fd:
            for _ in range(count):
                fd.write(zero1k)
        with open(varpath, "w") as fd:
            fd.write(f"URI: {fname}\n")
            fd.write("\n")
            fd.write(f"URI: {fname}.gz\n")
            fd.write("Content-Type: text/plain\n")
            fd.write("Content-Encoding: x-gzip\n")
            fd.write("\n")
        return fpath
