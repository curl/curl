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

SUBDIRS = clients

TESTENV =                             \
testenv/__init__.py                   \
testenv/caddy.py                      \
testenv/certs.py                      \
testenv/client.py                     \
testenv/curl.py                       \
testenv/env.py                        \
testenv/httpd.py                      \
testenv/mod_curltest/mod_curltest.c   \
testenv/nghttpx.py                    \
testenv/ports.py                      \
testenv/vsftpd.py                     \
testenv/ws_echo_server.py

EXTRA_DIST =           \
CMakeLists.txt         \
config.ini.in          \
conftest.py            \
requirements.txt       \
scorecard.py           \
test_01_basic.py       \
test_02_download.py    \
test_03_goaway.py      \
test_04_stuttered.py   \
test_05_errors.py      \
test_06_eyeballs.py    \
test_07_upload.py      \
test_08_caddy.py       \
test_09_push.py        \
test_10_proxy.py       \
test_11_unix.py        \
test_12_reuse.py       \
test_13_proxy_auth.py  \
test_14_auth.py        \
test_15_tracing.py     \
test_16_info.py        \
test_17_ssl_use.py     \
test_18_methods.py     \
test_19_shutdown.py    \
test_20_websockets.py  \
test_30_vsftpd.py      \
test_31_vsftpds.py     \
$(TESTENV)

clean-local:
	rm -rf *.pyc __pycache__
	rm -rf gen

check: clients

clients:
	@(cd clients; $(MAKE) check)

checksrc:
	cd clients && $(MAKE) checksrc
