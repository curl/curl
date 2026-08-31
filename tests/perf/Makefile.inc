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

BUNDLE = perf

# Files referenced from the bundle source
FIRST_C = first.c
FIRST_H = first.h

# Common files used by the performance test programs
UTILS_C =
UTILS_H =

CURLX_C = \
  ../../lib/curlx/base64.c \
  ../../lib/curlx/fopen.c \
  ../../lib/curlx/multibyte.c \
  ../../lib/curlx/strparse.c \
  ../../lib/curlx/timeval.c \
  ../../lib/curlx/warnless.c

# All performance test programs
TESTS_C = \
  base64.c \
  percent.c \
  snprintf.c \
  urlparser.c
