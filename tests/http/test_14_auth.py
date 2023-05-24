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

from testenv import Env, CurlClient, LocalClient


log = logging.getLogger(__name__)


class TestAuth:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, httpd, nghttpx):
        if env.have_h3():
            nghttpx.start_if_needed()
        httpd.clear_extra_configs()
        httpd.reload()

    # download 1 file, not authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_01_digest_get_noauth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto)
        r.check_response(http_status=401)

    # download 1 file, authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_02_digest_get_auth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_download(urls=[url], alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        r.check_response(http_status=200)

    # PUT data, authenticated
    @pytest.mark.parametrize("proto", ['http/1.1', 'h2', 'h3'])
    def test_14_03_digest_put_auth(self, env: Env, httpd, nghttpx, repeat, proto):
        if proto == 'h3' and not env.have_h3():
            pytest.skip("h3 not supported")
        data='0123456789'
        curl = CurlClient(env=env)
        url = f'https://{env.authority_for(env.domain1, proto)}/restricted/digest/data.json'
        r = curl.http_upload(urls=[url], data=data, alpn_proto=proto, extra_args=[
            '--digest', '--user', 'test:test'
        ])
        r.check_response(http_status=200)
