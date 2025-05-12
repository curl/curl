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
import os
import pytest

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestPush:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        push_dir = os.path.join(httpd.docs_dir, 'push')
        if not os.path.exists(push_dir):
            os.makedirs(push_dir)
        env.make_data_file(indir=push_dir, fname="data1", fsize=1*1024)
        env.make_data_file(indir=push_dir, fname="data2", fsize=1*1024)
        env.make_data_file(indir=push_dir, fname="data3", fsize=1*1024)

    def httpd_configure(self, env, httpd):
        httpd.set_extra_config(env.domain1, [
            'H2EarlyHints on',
            '<Location /push/data1>',
            '  H2PushResource /push/data2',
            '</Location>',
            '<Location /push/data2>',
            '  H2PushResource /push/data1',
            '  H2PushResource /push/data3',
            '</Location>',
        ])
        # activate the new config
        httpd.reload_if_config_changed()

    # download a file that triggers a "103 Early Hints" response
    def test_09_01_h2_early_hints(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/push/data1'
        r = curl.http_download(urls=[url], alpn_proto='h2', with_stats=False,
                               with_headers=True)
        r.check_exit_code(0)
        assert len(r.responses) == 2, f'{r.responses}'
        assert r.responses[0]['status'] == 103, f'{r.responses}'
        assert 'link' in r.responses[0]['header'], f'{r.responses[0]}'
        assert r.responses[0]['header']['link'] == '</push/data2>; rel=preload', f'{r.responses[0]}'

    def test_09_02_h2_push(self, env: Env, httpd, configures_httpd):
        self.httpd_configure(env, httpd)
        # use localhost as we do not have resolve support in local client
        url = f'https://localhost:{env.https_port}/push/data1'
        client = LocalClient(name='h2-serverpush', env=env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        r = client.run(args=[url])
        r.check_exit_code(0)
        assert os.path.exists(client.download_file(0))
        assert os.path.exists(os.path.join(client.run_dir, 'push0')), r.dump_logs()
