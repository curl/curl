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
import logging
import os
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        push_dir = os.path.join(httpd.docs_dir, 'push')
        if not os.path.exists(push_dir):
            os.makedirs(push_dir)

    # download via http: proxy (no tunnel)
    def test_10_01_http_get(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'http://{env.proxy_domain}:{env.http_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.http_port}:127.0.0.1',
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)

    # download via https: proxy (no tunnel)
    def test_10_02_http_get(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'http://localhost:{env.http_port}/data.json'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=[
                                 '--proxy', f'https://{env.proxy_domain}:{env.https_port}/',
                                 '--resolve', f'{env.proxy_domain}:{env.https_port}:127.0.0.1',
                                 '--proxy-cacert', env.ca.cert_file,
                               ])
        assert r.exit_code == 0
        r.check_stats(count=1, exp_status=200)
