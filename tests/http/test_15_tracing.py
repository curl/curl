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
import re
import pytest

from testenv import Env
from testenv import CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
class TestTracing:

    # default verbose output
    def test_15_01_trace_defaults(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, def_tracing=False, extra_args=[
            '-v'
        ])
        r.check_response(http_status=200)
        trace = r.trace_lines
        assert len(trace) > 0

    # trace ids
    def test_15_02_trace_ids(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, def_tracing=False, extra_args=[
            '-v', '--trace-config', 'ids'
        ])
        r.check_response(http_status=200)
        for line in  r.trace_lines:
            m = re.match(r'^\[0-[0x]] .+', line)
            if m is None:
                assert False, f'no match: {line}'

    # trace ids+time
    def test_15_03_trace_ids_time(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, def_tracing=False, extra_args=[
            '-v', '--trace-config', 'ids,time'
        ])
        r.check_response(http_status=200)
        for line in  r.trace_lines:
            m = re.match(r'^([0-9:.]+) \[0-[0x]] .+', line)
            if m is None:
                assert False, f'no match: {line}'

    # trace all
    def test_15_04_trace_all(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, def_tracing=False, extra_args=[
            '-v', '--trace-config', 'all'
        ])
        r.check_response(http_status=200)
        found_tcp = False
        for line in  r.trace_lines:
            m = re.match(r'^([0-9:.]+) \[0-[0x]] .+', line)
            if m is None:
                assert False, f'no match: {line}'
            m = re.match(r'^([0-9:.]+) \[0-[0x]] .+ \[TCP].+', line)
            if m is not None:
                found_tcp = True
        assert found_tcp, f'TCP filter does not appear in trace "all": {r.stderr}'

    # trace all, no TCP, no time
    def test_15_05_trace_all(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'http://{env.domain1}:{env.http_port}/data.json'
        r = curl.http_get(url=url, def_tracing=False, extra_args=[
            '-v', '--trace-config', 'all,-tcp,-time'
        ])
        r.check_response(http_status=200)
        found_tcp = False
        for line in  r.trace_lines:
            m = re.match(r'^\[0-[0x]] .+', line)
            if m is None:
                assert False, f'no match: {line}'
            m = re.match(r'^\[0-[0x]] . \[TCP].+', line)
            if m is not None:
                found_tcp = True
        if found_tcp:
            assert False, f'TCP filter appears in trace "all,-tcp": {r.stderr}'
