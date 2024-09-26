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
import pytest

from testenv import Env, CurlClient


log = logging.getLogger(__name__)


class TestMethods:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload_if_config_changed()
        indir = httpd.docs_dir
        env.make_data_file(indir=indir, fname="data-10k", fsize=10*1024)
        env.make_data_file(indir=indir, fname="data-100k", fsize=100*1024)
        env.make_data_file(indir=indir, fname="data-1m", fsize=1024*1024)

    # download 1 file
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_18_01_delete(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/tweak?id=[0-{count-1}]'
        r = curl.http_delete(urls=[url], alpn_proto=proto)
        r.check_stats(count=count, http_status=204, exitcode=0)

    # make HTTP/2 in the server send
    # - HEADER frame with 204 and eos=0
    # - 10ms later DATA frame length=0 and eos=1
    # should be accepted
    def test_18_02_delete_h2_special(self, env: Env, httpd, nghttpx, repeat):
        proto = 'h2'
        count = 1
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/curltest/tweak?id=[0-{count-1}]'\
                '&chunks=1&chunk_size=0&chunk_delay=10ms'
        r = curl.http_delete(urls=[url], alpn_proto=proto)
        r.check_stats(count=count, http_status=204, exitcode=0)
