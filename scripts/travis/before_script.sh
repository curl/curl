#!/bin/bash
set -eo pipefail

./buildconf

if [ "$NGTCP2" = yes ]; then
  cd $HOME
  git clone --depth 1 -b openssl-quic-draft-23 https://github.com/tatsuhiro-t/openssl possl
  cd possl
  ./config enable-tls1_3 --prefix=$HOME/ngbuild
  make
  make install_sw

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
  ./configure PKG_CONFIG_PATH=$HOME/ngbuild/lib/pkgconfig LDFLAGS="-Wl,-rpath,$HOME/ngbuild/lib" --prefix=$HOME/ngbuild --enable-lib-only
  make
  make install
fi

if [ "$TRAVIS_OS_NAME" = linux -a "$BORINGSSL" ]; then
  cd $HOME
  git clone --depth=1 https://boringssl.googlesource.com/boringssl
  cd boringssl
  mkdir build
  cd build
  CXX="g++" CC="gcc" cmake -DCMAKE_BUILD_TYPE=release -DBUILD_SHARED_LIBS=1 ..
  make
  cd ..
  mkdir lib
  cd lib
  cp ../build/crypto/libcrypto.so .
  cp ../build/ssl/libssl.so .
  echo "BoringSSL lib dir: "`pwd`
  cd ../build
  make clean
  rm -f CMakeCache.txt
  CXX="g++" CC="gcc" cmake -DCMAKE_POSITION_INDEPENDENT_CODE=on ..
  make
  export LIBS=-lpthread
fi

if [ "$TRAVIS_OS_NAME" = linux -a "$QUICHE" ]; then
  cd $HOME
  git clone --depth=1 https://github.com/cloudflare/quiche.git
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source $HOME/.cargo/env
  cd $HOME/quiche
  QUICHE_BSSL_PATH=$HOME/boringssl cargo build -v --release --features pkg-config-meta
fi

# Install common libraries.
# The library build directories are set to be cached by .travis.yml. If you are
# changing a build directory name below (eg a version change) then you must
# change it in .travis.yml `cache: directories:` as well.
if [ $TRAVIS_OS_NAME = linux ]; then
  if [ ! -e $HOME/wolfssl-4.0.0-stable/Makefile ]; then
    cd $HOME
    curl -LO https://github.com/wolfSSL/wolfssl/archive/v4.0.0-stable.tar.gz
    tar -xzf v4.0.0-stable.tar.gz
    cd wolfssl-4.0.0-stable
    ./autogen.sh
    ./configure --enable-tls13 --enable-all
    touch wolfssl/wolfcrypt/fips.h
    make
  fi

  cd $HOME/wolfssl-4.0.0-stable
  sudo make install

  if [ ! -e $HOME/mesalink-1.0.0/Makefile ]; then
    cd $HOME
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
    curl -LO https://github.com/mesalock-linux/mesalink/archive/v1.0.0.tar.gz
    tar -xzf v1.0.0.tar.gz
    cd mesalink-1.0.0
    ./autogen.sh
    ./configure --enable-tls13
    make
  fi

  cd $HOME/mesalink-1.0.0
  sudo make install

  if [ ! -e $HOME/nghttp2-1.39.2/Makefile ]; then
    cd $HOME
    curl -LO https://github.com/nghttp2/nghttp2/releases/download/v1.39.2/nghttp2-1.39.2.tar.gz
    tar -xzf nghttp2-1.39.2.tar.gz
    cd nghttp2-1.39.2
    CXX="g++-8" CC="gcc-8" CFLAGS="" LDFLAGS="" LIBS="" ./configure --disable-threads --enable-app
    make
  fi

  cd $HOME/nghttp2-1.39.2
  sudo make install
fi
