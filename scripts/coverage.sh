#!/bin/sh
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

autoreconf -fi
mkdir -p cvr
cd cvr
../configure --disable-shared --enable-debug --enable-maintainer-mode --enable-code-coverage
make -sj
# the regular test run
make TFLAGS=-n test-nonflaky
# make all allocs/file operations fail
#make TFLAGS=-n test-torture
# do everything event-based
make TFLAGS=-n test-event
lcov -d . -c -o cov.lcov
genhtml cov.lcov --output-directory coverage --title "curl code coverage"
tar -cjf curl-coverage.tar.bz2 coverage
