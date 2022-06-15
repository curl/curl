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

if [ "$NGTCP2" = yes ]; then
  if [ "$TRAVIS_OS_NAME" = linux -a "$GNUTLS" ]; then
    cd $HOME
    git clone --depth 1 https://gitlab.com/gnutls/nettle.git
    cd nettle
    ./.bootstrap
    ./configure LDFLAGS="-Wl,-rpath,$HOME/ngbuild/lib" --disable-documentation --prefix=$HOME/ngbuild
    make
    make install

    cd $HOME
    git clone --depth 1 -b 3.7.4 https://gitlab.com/gnutls/gnutls.git pgtls
    cd pgtls
    ./bootstrap
    ./configure PKG_CONFIG_PATH=$HOME/ngbuild/lib/pkgconfig LDFLAGS="-Wl,-rpath,$HOME/ngbuild/lib" --with-included-libtasn1 --with-included-unistring --disable-guile --disable-doc --disable-tools --without-zstd --disable-psk-authentication --prefix=$HOME/ngbuild
    make
    make install
  else
    cd $HOME
    git clone --depth 1 -b OpenSSL_1_1_1j+quic https://github.com/quictls/openssl possl
    cd possl
    ./config enable-tls1_3 --prefix=$HOME/ngbuild
    make
    make install_sw
  fi

  cd $HOME
  git clone --depth 1 https://github.com/ngtcp2/nghttp3
  cd nghttp3
  autoreconf -i
  ./configure --prefix=$HOME/ngbuild --enable-lib-only
  make
  make install

  cd $HOME
  git clone --depth 1 https://github.com/ngtcp2/ngtcp2
  cd ngtcp2
  autoreconf -i
  if test -n "$GNUTLS"; then
      WITHGNUTLS="--with-gnutls"
  fi
  ./configure PKG_CONFIG_PATH=$HOME/ngbuild/lib/pkgconfig LDFLAGS="-Wl,-rpath,$HOME/ngbuild/lib" --prefix=$HOME/ngbuild --enable-lib-only $WITHGNUTLS
  make
  make install
fi

if [ "$TRAVIS_OS_NAME" = linux -a "$BORINGSSL" ]; then
  cd $HOME
  git clone --depth=1 https://boringssl.googlesource.com/boringssl
  cd boringssl
  mkdir -p build
  cd ./build
  CXX="g++" CC="gcc" cmake .. -GNinja -DCMAKE_BUILD_TYPE=release -DBUILD_SHARED_LIBS=1
  cd ..
  cmake --build build
  mkdir lib
  cp ./build/crypto/libcrypto.so ./lib/
  cp ./build/ssl/libssl.so ./lib/
  echo "BoringSSL lib dir: "`pwd`"/lib"
  cmake --build build --target clean
  rm -f build/CMakeCache.txt
  cd ./build
  CXX="g++" CC="gcc" cmake .. -GNinja -DCMAKE_POSITION_INDEPENDENT_CODE=on
  cd ..
  cmake --build build
  export LIBS=-lpthread
fi

if [ "$TRAVIS_OS_NAME" = linux -a "$LIBRESSL" ]; then
  cd $HOME
  git clone --depth=1 -b v3.1.4 https://github.com/libressl-portable/portable.git libressl-git
  cd libressl-git
  ./autogen.sh
  ./configure --prefix=$HOME/libressl
  make
  make install
fi

if [ "$TRAVIS_OS_NAME" = linux -a "$QUICHE" ]; then
  cd $HOME
  git clone --depth=1 --recursive https://github.com/cloudflare/quiche.git
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source $HOME/.cargo/env
  cd $HOME/quiche

  #### Work-around https://github.com/curl/curl/issues/7927 #######
  #### See https://github.com/alexcrichton/cmake-rs/issues/131 ####
  sed -i -e 's/cmake = "0.1"/cmake = "=0.1.45"/' quiche/Cargo.toml

  cargo build -v --package quiche --release --features ffi,pkg-config-meta,qlog
  mkdir -v quiche/deps/boringssl/src/lib
  ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) quiche/deps/boringssl/src/lib/
fi
