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
from datetime import timedelta
import pytest

from testenv import Env, CurlClient, LocalClient, ExecResult


log = logging.getLogger(__name__)


class TestInfo:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=indir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=indir, fname="data-1m", fsize=1024*1024)

    # download plain file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_16_01_info_download(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True)
        r.check_stats(count=count, http_status=200, exitcode=0,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')
        for idx, s in enumerate(r.stats):
            self.check_stat(idx, s, r, dl_size=30, ul_size=0)

    # download plain file with a 302 redirect
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_16_02_info_302_download(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/data.json.302?[0-{count-1}]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True, extra_args=[
            '--location'
        ])
        r.check_stats(count=count, http_status=200, exitcode=0,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')
        for idx, s in enumerate(r.stats):
            self.check_stat(idx, s, r, dl_size=30, ul_size=0)

    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_16_03_info_upload(self, env: Env, httpd, nghttpx, proto, repeat):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 2
        fdata = os.path.join(env.gen_dir, 'data-100k')
        fsize = 100 * 1024
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/echo?id=[0-{count-1}]'
        r = curl.http_upload(urls=[url], data=f'@{fdata}', alpn_proto=proto,
                             with_headers=True, extra_args=[
                                '--trace-config', 'http/2,http/3'
                             ])
        r.check_response(count=count, http_status=200)
        r.check_stats(count=count, http_status=200, exitcode=0,
                      remote_port=env.port_for(alpn_proto=proto),
                      remote_ip='127.0.0.1')
        for idx, s in enumerate(r.stats):
            self.check_stat(idx, s, r, dl_size=fsize, ul_size=fsize)

    # download plain file via http: ('time_appconnect' is 0)
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_16_04_info_http_download(self, env: Env, httpd, nghttpx, repeat, proto):
        count = 2
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[url], alpn_proto=proto, with_stats=True)
        r.check_stats(count=count, http_status=200, exitcode=0,
                      remote_port=env.http_port, remote_ip='127.0.0.1')
        for idx, s in enumerate(r.stats):
            self.check_stat(idx, s, r, dl_size=30, ul_size=0)

    def check_stat(self, idx, s, r, dl_size=None, ul_size=None):
        self.check_stat_times(s, idx)
        # we always send something
        self.check_stat_positive(s, idx, 'size_request')
        # we always receive response headers
        self.check_stat_positive(s, idx, 'size_header')
        if ul_size is not None:
            assert s['size_upload'] == ul_size, f'stat #{idx}\n{r.dump_logs()}'  # the file we sent
        assert s['size_request'] >= s['size_upload'], \
            f'stat #{idx}, "size_request" smaller than "size_upload", {s}\n{r.dump_logs()}'
        if dl_size is not None:
            assert s['size_download'] == dl_size, f'stat #{idx}\n{r.dump_logs()}'  # the file we received

    def check_stat_positive(self, s, idx, key):
        assert key in s, f'stat #{idx} "{key}" missing: {s}'
        assert s[key] > 0, f'stat #{idx} "{key}" not positive: {s}'

    def check_stat_zero(self, s, key):
        assert key in s, f'stat "{key}" missing: {s}'
        assert s[key] == 0, f'stat "{key}" not zero: {s}'

    def check_stat_times(self, s, idx):
        # check timings reported on a transfer for consistency
        url = s['url_effective']
        # all stat keys which reporting timings
        all_keys = set([
            'time_appconnect', 'time_connect', 'time_redirect',
            'time_pretransfer', 'time_starttransfer', 'time_total'
        ])
        # stat keys where we expect a positive value
        pos_keys = set(['time_pretransfer', 'time_starttransfer', 'time_total'])
        if s['num_connects'] > 0:
            pos_keys.add('time_connect')
            if url.startswith('https:'):
                pos_keys.add('time_appconnect')
        if s['num_redirects'] > 0:
            pos_keys.add('time_redirect')
        zero_keys = all_keys - pos_keys
        # assert all zeros are zeros and the others are positive
        for key in zero_keys:
            self.check_stat_zero(s, key)
        for key in pos_keys:
            self.check_stat_positive(s, idx, key)
        # assert that all timers before "time_pretransfer" are less or equal
        for key in ['time_appconnect', 'time_connect', 'time_namelookup']:
            assert s[key] < s['time_pretransfer'], f'time "{key}" larger than' \
                f'"time_pretransfer": {s}'
        # assert transfer start is after pretransfer
        assert s['time_pretransfer'] <= s['time_starttransfer'], f'"time_pretransfer" '\
            f'greater than "time_starttransfer", {s}'
        # assert that transfer start is before total
        assert s['time_starttransfer'] <= s['time_total'], f'"time_starttransfer" '\
            f'greater than "time_total", {s}'
