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

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
@pytest.mark.skipif(condition=Env.curl_uses_lib('bearssl'), reason='BearSSL too slow')
class TestReuse:

    # check if HTTP/1.1 handles 'Connection: close' correctly
    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_01_h1_conn_close(self, env: Env,
                                 httpd, nghttpx, repeat, proto):
        httpd.clear_extra_configs()
        httpd.set_extra_config('base', [
            f'MaxKeepAliveRequests 1',
        ])
        httpd.reload()
        count = 100
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto)
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)
        # Server sends `Connection: close` on every 2nd request, requiring
        # a new connection
        assert r.total_connects == count/2

    @pytest.mark.parametrize("proto", ['http/1.1'])
    def test_12_02_h1_conn_timeout(self, env: Env,
                                   httpd, nghttpx, repeat, proto):
        httpd.clear_extra_configs()
        httpd.set_extra_config('base', [
            f'KeepAliveTimeout 1',
        ])
        httpd.reload()
        count = 5
        curl = CurlClient(env=env)
        urln = f'https://{env.authority_for(env.domain1, proto)}/data.json?[0-{count-1}]'
        r = curl.http_download(urls=[urln], alpn_proto=proto, extra_args=[
            '--rate', '30/m',
        ])
        assert r.exit_code == 0
        r.check_stats(count=count, exp_status=200)
        # Connections time out on server before we send another request,
        assert r.total_connects == count
        # we do not see how often a request was retried in the stats, so
        # we cannot check that connection reuse attempted a connection that
        # was later detected to be "dead". We would like to
        # assert stat['retry_count'] == 0
