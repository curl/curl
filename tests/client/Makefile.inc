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
# Shared between CMakeLists.txt and Makefile.am

BUNDLE = clients

# Files referenced from the bundle source
FIRST_C = first.c
FIRST_H = first.h

CURLX_C = \
  ../../lib/curlx/multibyte.c \
  ../../lib/curlx/timediff.c \
  ../../lib/curlx/wait.c

# All test clients
TESTS_C = \
  h2_pausing.c \
  h2_serverpush.c \
  h2_upgrade_extreme.c \
  hx_download.c \
  hx_upload.c \
  tls_session_reuse.c \
  upload_pausing.c \
  ws_data.c \
  ws_pingpong.c
