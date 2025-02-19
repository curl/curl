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
import shutil
import pytest

from testenv import Env, CurlClient, VsFTPD


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.has_vsftpd(), reason="missing vsftpd")
class TestVsFTPD:

    @pytest.fixture(autouse=True, scope='class')
    def vsftpd(self, env):
        vsftpd = VsFTPD(env=env)
        assert vsftpd.start()
        yield vsftpd
        vsftpd.stop()

    def _make_docs_file(self, docs_dir: str, fname: str, fsize: int):
        fpath = os.path.join(docs_dir, fname)
        data1k = 1024*'x'
        flen = 0
        with open(fpath, 'w') as fd:
            while flen < fsize:
                fd.write(data1k)
                flen += len(data1k)
        return flen

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, vsftpd):
        if os.path.exists(vsftpd.docs_dir):
            shutil.rmtree(vsftpd.docs_dir)
        if not os.path.exists(vsftpd.docs_dir):
            os.makedirs(vsftpd.docs_dir)
        self._make_docs_file(docs_dir=vsftpd.docs_dir, fname='data-1k', fsize=1024)
        self._make_docs_file(docs_dir=vsftpd.docs_dir, fname='data-10k', fsize=10*1024)
        self._make_docs_file(docs_dir=vsftpd.docs_dir, fname='data-1m', fsize=1024*1024)
        self._make_docs_file(docs_dir=vsftpd.docs_dir, fname='data-10m', fsize=10*1024*1024)
        env.make_data_file(indir=env.gen_dir, fname="upload-1k", fsize=1024)
        env.make_data_file(indir=env.gen_dir, fname="upload-100k", fsize=100*1024)
        env.make_data_file(indir=env.gen_dir, fname="upload-1m", fsize=1024*1024)

    def test_30_01_list_dir(self, env: Env, vsftpd: VsFTPD):
        curl = CurlClient(env=env)
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/'
        r = curl.ftp_get(urls=[url], with_stats=True)
        r.check_stats(count=1, http_status=226)
        lines = open(os.path.join(curl.run_dir, 'download_#1.data')).readlines()
        assert len(lines) == 4, f'list: {lines}'

    # download 1 file, no SSL
    @pytest.mark.parametrize("docname", [
        'data-1k', 'data-1m', 'data-10m'
    ])
    def test_30_02_download_1(self, env: Env, vsftpd: VsFTPD, docname):
        curl = CurlClient(env=env)
        srcfile = os.path.join(vsftpd.docs_dir, f'{docname}')
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/{docname}?[0-{count-1}]'
        r = curl.ftp_get(urls=[url], with_stats=True)
        r.check_stats(count=count, http_status=226)
        self.check_downloads(curl, srcfile, count)

    @pytest.mark.parametrize("docname", [
        'data-1k', 'data-1m', 'data-10m'
    ])
    def test_30_03_download_10_serial(self, env: Env, vsftpd: VsFTPD, docname):
        curl = CurlClient(env=env)
        srcfile = os.path.join(vsftpd.docs_dir, f'{docname}')
        count = 10
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/{docname}?[0-{count-1}]'
        r = curl.ftp_get(urls=[url], with_stats=True)
        r.check_stats(count=count, http_status=226)
        self.check_downloads(curl, srcfile, count)
        assert r.total_connects == count + 1, 'should reuse the control conn'

    @pytest.mark.parametrize("docname", [
        'data-1k', 'data-1m', 'data-10m'
    ])
    def test_30_04_download_10_parallel(self, env: Env, vsftpd: VsFTPD, docname):
        curl = CurlClient(env=env)
        srcfile = os.path.join(vsftpd.docs_dir, f'{docname}')
        count = 10
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/{docname}?[0-{count-1}]'
        r = curl.ftp_get(urls=[url], with_stats=True, extra_args=[
            '--parallel'
        ])
        r.check_stats(count=count, http_status=226)
        self.check_downloads(curl, srcfile, count)
        assert r.total_connects > count + 1, 'should have used several control conns'

    @pytest.mark.parametrize("docname", [
        'upload-1k', 'upload-100k', 'upload-1m'
    ])
    def test_30_05_upload_1(self, env: Env, vsftpd: VsFTPD, docname):
        curl = CurlClient(env=env)
        srcfile = os.path.join(env.gen_dir, docname)
        dstfile = os.path.join(vsftpd.docs_dir, docname)
        self._rmf(dstfile)
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/'
        r = curl.ftp_upload(urls=[url], fupload=f'{srcfile}', with_stats=True)
        r.check_stats(count=count, http_status=226)
        self.check_upload(env, vsftpd, docname=docname)

    def _rmf(self, path):
        if os.path.exists(path):
            return os.remove(path)

    # check with `tcpdump` if curl causes any TCP RST packets
    @pytest.mark.skipif(condition=not Env.tcpdump(), reason="tcpdump not available")
    def test_30_06_shutdownh_download(self, env: Env, vsftpd: VsFTPD):
        docname = 'data-1k'
        curl = CurlClient(env=env)
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/{docname}?[0-{count-1}]'
        r = curl.ftp_get(urls=[url], with_stats=True, with_tcpdump=True)
        r.check_stats(count=count, http_status=226)
        assert r.tcpdump
        assert len(r.tcpdump.stats) == 0, 'Unexpected TCP RSTs packets'

    # check with `tcpdump` if curl causes any TCP RST packets
    @pytest.mark.skipif(condition=not Env.tcpdump(), reason="tcpdump not available")
    def test_30_07_shutdownh_upload(self, env: Env, vsftpd: VsFTPD):
        docname = 'upload-1k'
        curl = CurlClient(env=env)
        srcfile = os.path.join(env.gen_dir, docname)
        dstfile = os.path.join(vsftpd.docs_dir, docname)
        self._rmf(dstfile)
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/'
        r = curl.ftp_upload(urls=[url], fupload=f'{srcfile}', with_stats=True, with_tcpdump=True)
        r.check_stats(count=count, http_status=226)
        assert r.tcpdump
        assert len(r.tcpdump.stats) == 0, 'Unexpected TCP RSTs packets'

    def test_30_08_active_download(self, env: Env, vsftpd: VsFTPD):
        docname = 'data-10k'
        curl = CurlClient(env=env)
        srcfile = os.path.join(vsftpd.docs_dir, f'{docname}')
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/{docname}?[0-{count-1}]'
        r = curl.ftp_get(urls=[url], with_stats=True, extra_args=[
            '--ftp-port', '127.0.0.1'
        ])
        r.check_stats(count=count, http_status=226)
        self.check_downloads(curl, srcfile, count)

    def test_30_09_active_upload(self, env: Env, vsftpd: VsFTPD):
        docname = 'upload-1k'
        curl = CurlClient(env=env)
        srcfile = os.path.join(env.gen_dir, docname)
        dstfile = os.path.join(vsftpd.docs_dir, docname)
        self._rmf(dstfile)
        count = 1
        url = f'ftp://{env.ftp_domain}:{vsftpd.port}/'
        r = curl.ftp_upload(urls=[url], fupload=f'{srcfile}', with_stats=True, extra_args=[
            '--ftp-port', '127.0.0.1'
        ])
        r.check_stats(count=count, http_status=226)
        self.check_upload(env, vsftpd, docname=docname)

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

    def check_upload(self, env, vsftpd: VsFTPD, docname):
        srcfile = os.path.join(env.gen_dir, docname)
        dstfile = os.path.join(vsftpd.docs_dir, docname)
        assert os.path.exists(srcfile)
        assert os.path.exists(dstfile)
        if not filecmp.cmp(srcfile, dstfile, shallow=False):
            diff = "".join(difflib.unified_diff(a=open(srcfile).readlines(),
                                                b=open(dstfile).readlines(),
                                                fromfile=srcfile,
                                                tofile=dstfile,
                                                n=1))
            assert False, f'upload {dstfile} differs:\n{diff}'
