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
import difflib
import filecmp
import logging
import os
import pytest

from testenv import Env, CurlClient, Sshd


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_protocol('scp'), reason="curl built without scp:")
@pytest.mark.skipif(condition=not Env.has_sshd(), reason="missing sshd")
class TestScp:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, sshd):
        env.make_data_file(indir=sshd.home_dir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=sshd.home_dir, fname="data-10m", fsize=10*1024*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=env.gen_dir, fname="data-10m", fsize=10*1024*1024)

    def test_50_01_insecure(self, env: Env, sshd: Sshd):
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--insecure',
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)

    def test_50_02_unknown_hosts(self, env: Env, sshd: Sshd):
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--knownhosts', sshd.unknown_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(60)  # CURLE_PEER_FAILED_VERIFICATION

    def test_50_03_known_hosts(self, env: Env, sshd: Sshd):
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)

    # use key not in authorized_keys file
    def test_50_04_unauth_user(self, env: Env, sshd: Sshd):
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user2_pubkey_file,
            '--key', sshd.user2_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(67)  # CURLE_LOGIN_DENIED

    def test_50_10_dl_single(self, env: Env, sshd: Sshd):
        count = 1
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data-10k')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}?[0-{count-1}]'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        self.check_downloads(curl, doc_file, count)

    def test_50_11_dl_serial(self, env: Env, sshd: Sshd):
        count = 5
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data-10k')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}?[0-{count-1}]'
        r = curl.ssh_download(urls=[url], extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        self.check_downloads(curl, doc_file, count)

    def test_50_12_dl_parallel(self, env: Env, sshd: Sshd):
        count = 5
        curl = CurlClient(env=env)
        doc_file = os.path.join(sshd.home_dir, 'data-10k')
        url = f'scp://{env.domain1}:{sshd.port}/{doc_file}?[0-{count-1}]'
        r = curl.http_download(urls=[url], extra_args=[
            '--parallel',
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        self.check_downloads(curl, doc_file, count)

    def test_50_20_ul_single(self, env: Env, sshd: Sshd):
        srcfile = os.path.join(env.gen_dir, 'data-10k')
        destfile = os.path.join(sshd.home_dir, 'upload_20.data')
        curl = CurlClient(env=env)
        url = f'scp://{env.domain1}:{sshd.port}/{destfile}'
        r = curl.ssh_upload(urls=[url], fupload=srcfile, extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        self.check_upload(sshd, srcfile, destfile)

    def test_50_21_ul_serial(self, env: Env, sshd: Sshd):
        count = 5
        srcfile = os.path.join(env.gen_dir, 'data-10k')
        destfile = os.path.join(sshd.home_dir, 'upload_21.data')
        curl = CurlClient(env=env)
        url = f'scp://{env.domain1}:{sshd.port}/{destfile}.[0-{count-1}]'
        r = curl.ssh_upload(urls=[url], fupload=srcfile, extra_args=[
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        for i in range(count):
            self.check_upload(sshd, srcfile, f'{destfile}.{i}')

    def test_50_22_ul_parallel(self, env: Env, sshd: Sshd):
        count = 5
        srcfile = os.path.join(env.gen_dir, 'data-10k')
        destfile = os.path.join(sshd.home_dir, 'upload_22.data')
        curl = CurlClient(env=env)
        url = f'scp://{env.domain1}:{sshd.port}/{destfile}.[0-{count-1}]'
        r = curl.ssh_upload(urls=[url], fupload=srcfile, extra_args=[
            '--parallel',
            '--knownhosts', sshd.known_hosts,
            '--pubkey', sshd.user1_pubkey_file,
            '--key', sshd.user1_privkey_file,
            '--user', f'{os.environ["USER"]}:',
        ])
        r.check_exit_code(0)
        for i in range(count):
            self.check_upload(sshd, srcfile, f'{destfile}.{i}')

    def check_downloads(self, client, srcfile: str, count: int,
                        complete: bool = True):
        for i in range(count):
            dfile = client.download_file(i)
            assert os.path.exists(dfile)
            if complete and not filecmp.cmp(srcfile, dfile, shallow=False):
                diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                    b=open(dfile).readlines(),
                                                    fromfile=srcfile,
                                                    tofile=dfile,
                                                    n=1))
                assert False, f'download {dfile} differs:\n{diff}'

    def check_upload(self, sshd: Sshd, srcfile, destfile, binary=True):
        assert os.path.exists(srcfile)
        assert os.path.exists(destfile)
        if not filecmp.cmp(srcfile, destfile, shallow=False):
            diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                b=open(destfile).readlines(),
                                                fromfile=srcfile,
                                                tofile=destfile,
                                                n=1))
            assert not binary and len(diff) == 0, f'upload {destfile} differs:\n{diff}'
