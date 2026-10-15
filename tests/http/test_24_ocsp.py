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
import shutil
import socket
import subprocess
import time
from typing import Dict

import pytest
from testenv import CurlClient, Env
from testenv.ports import alloc_ports_and_do

log = logging.getLogger(__name__)


class OsslServer:

    def __init__(self, env, domain, ocsp_case):
        self.name = 'osslserver'
        self.env = env
        self.run_dir = os.path.join(env.gen_dir, self.name)
        self.err_file = os.path.join(self.run_dir, 'stderr')
        self._rmrf(self.run_dir)
        self._mkpath(self.run_dir)
        self.domain = domain
        self.ocsp_case = ocsp_case
        self.sproc = None
        self.cerr = None
        self.port = 0

    def _mkpath(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)

    def _mk_ocsp_stat(self, ocsp_file, creds, index_content):
        # make an OCSP status file for certificate 'creds' with
        # content 'index_content'
        ocsp_index = os.path.join(self.env.gen_dir, 'ocsp-index.der')
        with open(ocsp_index, 'w') as fd:
            fd.write(index_content)
        ocsp_req = os.path.join(self.env.gen_dir, 'ocsp-req.der')
        s = subprocess.run([
            self.env.CONFIG.openssl, 'ocsp',
            '-issuer', self.env.ca.cert_file,
            '-cert', creds.cert_file,
            '-no_nonce',
            '-reqout', ocsp_req
        ], stderr=self.cerr, stdout=self.cerr)
        assert s.returncode == 0
        s = subprocess.run([
            self.env.CONFIG.openssl, 'ocsp',
            '-index', ocsp_index,
            '-rsigner', self.env.ca.cert_file,
            '-rkey', self.env.ca.pkey_file,
            '-CA', self.env.ca.cert_file,
            '-reqin', ocsp_req,
            '-respout', ocsp_file,
            '-ndays', '1'
        ], stderr=self.cerr, stdout=self.cerr)
        assert s.returncode == 0

    def startup(self):
        self.cerr = open(self.err_file, 'w')  # noqa: SIM115
        creds = self.env.get_credentials(self.domain)
        assert creds  # convince pytype this is not None
        ocsp_file = os.path.join(self.env.gen_dir, 'ocsp-stat.der')
        if self.ocsp_case == 'trylater':
            with open(ocsp_file, 'w') as fd:
                fd.write('\x30\x03\x0a\x01\x03')
        elif self.ocsp_case == 'unauth':
            with open(ocsp_file, 'w') as fd:
                fd.write('\x30\x03\x0a\x01\x06')
        elif self.ocsp_case == 'interror':
            with open(ocsp_file, 'w') as fd:
                fd.write('\x30\x03\x0a\x01\x02')
        elif self.ocsp_case == 'unknown':
            self._mk_ocsp_stat(ocsp_file, creds, '')
        elif self.ocsp_case == 'revoked':
            index_file = os.path.join(self.env.gen_dir, 'ocsp-index.txt')
            serial = hex(creds.serial_number)[2:].upper()
            index = 'R\t301231000000Z\t240101000000Z,keyCompromise' \
                f'\t{serial}\tunknown\t/{creds.subject.rfc4514_string()}\n'
            with open(index_file, 'w') as fd:
                fd.write(index)
            self._mk_ocsp_stat(ocsp_file, creds, index)
        elif self.ocsp_case == 'valid':
            index_file = os.path.join(self.env.gen_dir, 'ocsp-index.txt')
            serial = hex(creds.serial_number)[2:].upper()
            index = 'V\t301231000000Z\t240101000000Z,valid' \
                f'\t{serial}\tunknown\t/{creds.subject.rfc4514_string()}\n'
            with open(index_file, 'w') as fd:
                fd.write(index)
            self._mk_ocsp_stat(ocsp_file, creds, index)
        elif self.ocsp_case:
            assert False, f'unknown ocsp case: {self.ocsp_case}'

        def startup(ports: Dict[str, int]) -> bool:
            self.port = ports[self.name]
            sargs = [
                self.env.CONFIG.openssl, 's_server', '-www',
                '-accept', f'{self.port}', '-tls1_2',
                '-cert',  creds.cert_file, '-key', creds.pkey_file,
            ]
            if self.ocsp_case is not None:
                sargs.extend(['-status_file', ocsp_file])
            log.info(f'start_ {sargs}')
            self.sproc = subprocess.Popen(args=sargs,
                                          cwd=self.run_dir,
                                          stderr=self.cerr,
                                          stdout=self.cerr)
            self.env.update_ports(ports)
            return True

        port_spec = {
            self.name: socket.SOCK_STREAM
        }
        assert alloc_ports_and_do(port_spec, startup,
                                  self.env.gen_root, max_tries=3)
        assert self.sproc

    def shutdown(self):
        self.sproc.terminate()
        self.cerr.close()

    def set_ocsp_case(self, ocsp_case):
        if self.ocsp_case != ocsp_case:
            self.shutdown()
            self.ocsp_case = ocsp_case
            self.startup()


@pytest.mark.skipif(condition=not Env.have_openssl_ech(), reason="no modern openssl available")
@pytest.mark.skipif(condition=not Env.curl_uses_lib('mbedtls'), reason="no cert-status in mbedtls")
@pytest.mark.skipif(condition=not Env.curl_uses_lib('rustls'), reason="no cert-status in rustls")
@pytest.mark.skipif(condition=not Env.curl_uses_lib('schannel'), reason="no cert-status in schannel")
class TestOCSP:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def osslserver(cls, env):
        server = OsslServer(env, env.domain1, None)
        server.startup()
        yield server
        server.shutdown()

    @pytest.mark.parametrize("cert_status, exp_ok, ocsp_case", [
        [False, True, None],
        [True, False, None],  # CURLE_SSL_INVALIDCERTSTATUS
        [True, False, 'trylater'],
        [True, False, 'unauth'],
        [True, False, 'interror'],
        [True, False, 'unknown'],
        [True, False, 'revoked'],
        [True,  True, 'valid'],
    ])
    def test_24_01_verify_status(self, env: Env, osslserver, cert_status, exp_ok, ocsp_case):
        osslserver.set_ocsp_case(ocsp_case)
        run_env = os.environ.copy()
        xargs = []
        if cert_status:
            xargs.append('--cert-status')
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{osslserver.port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=xargs)
        if exp_ok:
            r.check_exit_code(0)
        else:
            assert r.exit_code in [60, 91], f'{r}'
