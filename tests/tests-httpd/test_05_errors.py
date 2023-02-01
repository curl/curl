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
import json
import logging
from typing import Optional, Tuple, List, Dict
import pytest

from testenv import Env, CurlClient, ExecResult


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
@pytest.mark.skipif(condition=not Env.httpd_is_at_least('2.4.55'),
                    reason=f"httpd version too old for this: {Env.httpd_version()}")
class TestErrors:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()

    # download 1 file, check that we get CURLE_PARTIAL_FILE
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_05_01_partial_1(self, env: Env, httpd, nghttpx, repeat,
                              proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count - 1}]'\
               '&chunks=3&chunk_size=16000&body_error=reset'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code != 0, f'{r}'
        invalid_stats = []
        for idx, s in enumerate(r.stats):
            if 'exitcode' not in s or s['exitcode'] not in [18, 56]:
                invalid_stats.append(f'request {idx} exit with {s["exitcode"]}')
        assert len(invalid_stats) == 0, f'failed: {invalid_stats}'

    # download 20 file, check that we get CURLE_PARTIAL_FILE for all
    @pytest.mark.parametrize("proto", ['h2', 'h3'])
    def test_05_02_partial_20(self, env: Env, httpd, nghttpx, repeat,
                              proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 20
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}' \
               f'/curltest/tweak?id=[0-{count - 1}]'\
               '&chunks=3&chunk_size=16000&body_error=reset'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code != 0, f'{r}'
        assert len(r.stats) == count, f'did not get all stats: {r}'
        invalid_stats = []
        for idx, s in enumerate(r.stats):
            if 'exitcode' not in s or s['exitcode'] not in [18, 56]:
                invalid_stats.append(f'request {idx} exit with {s["exitcode"]}')
        assert len(invalid_stats) == 0, f'failed: {invalid_stats}'
