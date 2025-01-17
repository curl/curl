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
from typing import Tuple, List, Dict
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env().slow_network, reason="not suitable for slow network tests")
@pytest.mark.skipif(condition=Env().ci_run, reason="not suitable for CI runs")
class TestStuttered:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    # download 1 file, check that delayed response works in general
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_04_01_download_1(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count - 1}]'\
               '&chunks=100&chunk_size=100&chunk_delay=10ms'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        r.check_response(count=1, http_status=200)

    # download 50 files in 100 chunks a 100 bytes with 10ms delay between
    # prepend 100 file requests to warm up connection processing limits
    # (Apache2 increases # of parallel processed requests after successes)
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_04_02_100_100_10(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        warmups = 100
        curl = CurlClient(env=env)
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{warmups-1}]'
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count-1}]'\
               '&chunks=100&chunk_size=100&chunk_delay=10ms'
        r = curl.http_download(urls=[url1, urln], alpn_proto=proto,
                               extra_args=['--parallel'])
        r.check_response(count=warmups+count, http_status=200)
        assert r.total_connects == 1
        t_avg, i_min, t_min, i_max, t_max = self.stats_spread(r.stats[warmups:], 'time_total')
        if t_max < (5 * t_min) and t_min < 2:
            log.warning(f'avg time of transfer: {t_avg} [{i_min}={t_min}, {i_max}={t_max}]')

    # download 50 files in 1000 chunks a 10 bytes with 1ms delay between
    # prepend 100 file requests to warm up connection processing limits
    # (Apache2 increases # of parallel processed requests after successes)
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_04_03_1000_10_1(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        warmups = 100
        curl = CurlClient(env=env)
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{warmups-1}]'
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count - 1}]'\
               '&chunks=1000&chunk_size=10&chunk_delay=100us'
        r = curl.http_download(urls=[url1, urln], alpn_proto=proto,
                               extra_args=['--parallel'])
        r.check_response(count=warmups+count, http_status=200)
        assert r.total_connects == 1
        t_avg, i_min, t_min, i_max, t_max = self.stats_spread(r.stats[warmups:], 'time_total')
        if t_max < (5 * t_min):
            log.warning(f'avg time of transfer: {t_avg} [{i_min}={t_min}, {i_max}={t_max}]')

    # download 50 files in 10000 chunks a 1 byte with 10us delay between
    # prepend 100 file requests to warm up connection processing limits
    # (Apache2 increases # of parallel processed requests after successes)
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_04_04_1000_10_1(self, env: Env, httpd, nghttpx, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 50
        warmups = 100
        curl = CurlClient(env=env)
        url1 = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{warmups-1}]'
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count - 1}]'\
               '&chunks=10000&chunk_size=1&chunk_delay=50us'
        r = curl.http_download(urls=[url1, urln], alpn_proto=proto,
                               extra_args=['--parallel'])
        r.check_response(count=warmups+count, http_status=200)
        assert r.total_connects == 1
        t_avg, i_min, t_min, i_max, t_max = self.stats_spread(r.stats[warmups:], 'time_total')
        if t_max < (5 * t_min):
            log.warning(f'avg time of transfer: {t_avg} [{i_min}={t_min}, {i_max}={t_max}]')

    def stats_spread(self, stats: List[Dict], key: str) -> Tuple[float, int, float, int, float]:
        stotals = 0.0
        s_min = 100.0
        i_min = -1
        s_max = 0.0
        i_max = -1
        for idx, s in enumerate(stats):
            val = float(s[key])
            stotals += val
            if val > s_max:
                s_max = val
                i_max = idx
            if val < s_min:
                s_min = val
                i_min = idx
        return stotals/len(stats), i_min, s_min, i_max, s_max
