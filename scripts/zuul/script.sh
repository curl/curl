#!/bin/bash
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
set -eo pipefail

autoreconf -fi

if [ "$T" = "coverage" ]; then
  ./configure --enable-debug --disable-shared --disable-threaded-resolver --enable-code-coverage --enable-werror --with-libssh2
  make
  make TFLAGS=-n test-nonflaky
  make "TFLAGS=-n -e" test-nonflaky
  tests="1 200 300 500 700 800 900 1000 1100 1200 1302 1400 1502 3000"
  make "TFLAGS=-n -t $tests" test-nonflaky
  coveralls --gcov /usr/bin/gcov-8 --gcov-options '\-lp' -i src -e lib -e tests -e docs -b $PWD/src
  coveralls --gcov /usr/bin/gcov-8 --gcov-options '\-lp' -e src -i lib -e tests -e docs -b $PWD/lib
fi

if [ "$T" = "torture" ]; then
  ./configure --enable-debug --disable-shared --disable-threaded-resolver --enable-code-coverage --enable-werror --with-libssh2 --with-openssl
  make
  tests="!TLS-SRP !FTP"
  make "TFLAGS=-n --shallow=20 -t $tests" test-nonflaky
fi

if [ "$T" = "debug" ]; then
  ./configure --enable-debug --enable-werror $C
  make
  make examples
  if [ -z $NOTESTS ]; then
    make test-nonflaky
  fi
fi

if [ "$T" = "debug-bearssl" ]; then
  ./configure --enable-debug --enable-werror $C
  make
  make "TFLAGS=-n !313" test-nonflaky
fi

if [ "$T" = "novalgrind" ]; then
  ./configure --enable-werror $C
  make
  make examples
  make TFLAGS=-n test-nonflaky
fi

if [ "$T" = "normal" ]; then
  if [ $TRAVIS_OS_NAME = linux ]; then
    # Remove system curl to make sure we don't rely on it.
    # Only done on Linux since we're not permitted to on mac.
    sudo rm -f /usr/bin/curl
  fi
  ./configure --enable-warnings --enable-werror $C
  make
  make examples
  if [ -z $NOTESTS ]; then
    make test-nonflaky
  fi
  if [ -n "$CHECKSRC" ]; then
    make checksrc
  fi
fi

if [ "$T" = "cmake" ]; then
  mkdir -p build
  cd ./build
  cmake .. -DCURL_WERROR=ON $C
  cd ..
  cmake --build build
  env TFLAGS="!1139 $TFLAGS" cmake --build build --target test-nonflaky
fi
