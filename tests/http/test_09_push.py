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

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=Env.setup_incomplete(),
                    reason=f"missing: {Env.incomplete_reason()}")
class TestPush:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd):
        push_dir = os.path.join(httpd.docs_dir, 'push')
        if not os.path.exists(push_dir):
            os.makedirs(push_dir)
        env.make_data_file(indir=push_dir, fname="data1", fsize=100*1024)
        env.make_data_file(indir=push_dir, fname="data2", fsize=100*1024)
        env.make_data_file(indir=push_dir, fname="data3", fsize=100*1024)
        httpd.set_extra_config(env.domain1, [
            f'H2EarlyHints on',
            f'<Location /push/data1>',
            f'  H2PushResource /push/data2',
            f'</Location>',
            f'<Location /push/data2>',
            f'  H2PushResource /push/data1',
            f'  H2PushResource /push/data3',
            f'</Location>',
        ])
        # activate the new config
        httpd.reload()
        yield
        httpd.clear_extra_configs()
        httpd.reload()

    # download a file that triggers a "103 Early Hints" response
    def test_09_01_early_hints(self, env: Env, httpd, repeat):
        curl = CurlClient(env=env)
        url = f'https://{env.domain1}:{env.https_port}/push/data1'
        r = curl.http_download(urls=[url], alpn_proto='h2', with_stats=False,
                               with_headers=True)
        assert r.exit_code == 0, f'{r}'
        assert len(r.responses) == 2, f'{r.responses}'
        assert r.responses[0]['status'] == 103, f'{r.responses}'
        assert 'link' in r.responses[0]['header'], f'{r.responses[0]}'
        assert r.responses[0]['header']['link'] == '</push/data2>; rel=preload', f'{r.responses[0]}'
