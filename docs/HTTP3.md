<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HTTP3 (and QUIC)

## Resources

[HTTP/3 Explained](https://http3-explained.haxx.se/en/) - the online free
book describing the protocols involved.

[quicwg.org](https://quicwg.org/) - home of the official protocol drafts

## QUIC libraries

QUIC libraries we are using:

[ngtcp2](https://github.com/ngtcp2/ngtcp2)

[quiche](https://github.com/cloudflare/quiche) - **EXPERIMENTAL**

## Experimental

HTTP/3 support using *quiche* in curl is considered **EXPERIMENTAL** until
further notice. Only the *ngtcp2* backend is not experimental.

Further development and tweaking of the HTTP/3 support in curl happens in the
master branch using pull-requests like ordinary changes.

To fix before we remove the experimental label:

- the used QUIC library needs to consider itself non-beta
- it is fine to "leave" individual backends as experimental if necessary

# ngtcp2 version

Building curl with ngtcp2 involves 3 components: `ngtcp2` itself, `nghttp3`
and a QUIC supporting TLS library. The supported TLS libraries are covered
below.

While any version of `ngtcp2` and `nghttp3` from v1.0.0 on are expected to
work, using the latest versions often brings functional and performance
improvements.

The build examples use `$NGHTTP3_VERSION` and `$NGTCP2_VERSION` as
placeholders for the version you build.

## Build with OpenSSL or fork

OpenSSL v3.5.0+ requires *ngtcp2* v1.12.0+. Earlier versions do not work.

Build OpenSSL (v3.5.0+) or fork AWS-LC, BoringSSL, LibreSSL or quictls:

     # Instructions for OpenSSL v3.5.0+
     % git clone --depth 1 -b openssl-$OPENSSL_VERSION https://github.com/openssl/openssl
     % cd openssl
     % ./config --prefix=/path/to/openssl --libdir=lib
     % make
     % make install

Build nghttp3:

     % cd ..
     % git clone -b $NGHTTP3_VERSION https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % git submodule update --init
     % autoreconf -fi
     % ./configure --prefix=/path/to/nghttp3 --enable-lib-only
     % make
     % make install

Build ngtcp2:

     % cd ..
     % git clone -b $NGTCP2_VERSION https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     # Change --with-openssl to --with-boringssl for AWS-LC and BoringSSL
     % ./configure PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/path/to/openssl/lib" --prefix=/path/to/ngtcp2 --enable-lib-only --with-openssl
     % make
     % make install

Build curl (with autotools):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig LDFLAGS="-Wl,-rpath,/path/to/openssl/lib" --with-openssl=/path/to/openssl --with-ngtcp2=/path/to/ngtcp2 --with-nghttp3=/path/to/nghttp3
     % make
     % make install

Build curl (with CMake):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig:/path/to/ngtcp2/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig cmake -B bld -DOPENSSL_ROOT_DIR=/path/to/openssl -DUSE_NGTCP2=ON
     % cmake --build bld

## Build with GnuTLS

Build GnuTLS:

     % git clone --depth 1 https://gitlab.com/gnutls/gnutls
     % cd gnutls
     % ./bootstrap
     % ./configure --prefix=/path/to/gnutls
     % make
     % make install

Build nghttp3:

     % cd ..
     % git clone -b $NGHTTP3_VERSION https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % git submodule update --init
     % autoreconf -fi
     % ./configure --prefix=/path/to/nghttp3 --enable-lib-only
     % make
     % make install

Build ngtcp2:

     % cd ..
     % git clone -b $NGTCP2_VERSION https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=/path/to/gnutls/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/path/to/gnutls/lib" --prefix=/path/to/ngtcp2 --enable-lib-only --with-gnutls
     % make
     % make install

Build curl (with autotools):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=/path/to/gnutls/lib/pkgconfig --with-gnutls=/path/to/gnutls --with-ngtcp2=/path/to/ngtcp2 --with-nghttp3=/path/to/nghttp3
     % make
     % make install

Build curl (with CMake):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % PKG_CONFIG_PATH=/path/to/gnutls/lib/pkgconfig:/path/to/ngtcp2/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig cmake -B bld -DCURL_USE_GNUTLS=ON -DUSE_NGTCP2=ON
     % cmake --build bld

## Build with wolfSSL

Build wolfSSL:

     % git clone https://github.com/wolfSSL/wolfssl
     % cd wolfssl
     % autoreconf -fi
     % ./configure --prefix=/path/to/wolfssl --enable-quic --enable-session-ticket --enable-earlydata --enable-psk --enable-harden --enable-altcertchains
     % make
     % make install

Build nghttp3:

     % cd ..
     % git clone -b $NGHTTP3_VERSION https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % git submodule update --init
     % autoreconf -fi
     % ./configure --prefix=/path/to/nghttp3 --enable-lib-only
     % make
     % make install

Build ngtcp2:

     % cd ..
     % git clone -b $NGTCP2_VERSION https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=/path/to/wolfssl/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/path/to/wolfssl/lib" --prefix=/path/to/ngtcp2 --enable-lib-only --with-wolfssl
     % make
     % make install

Build curl (with autotools):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=/path/to/wolfssl/lib/pkgconfig --with-wolfssl=/path/to/wolfssl --with-ngtcp2=/path/to/ngtcp2 --with-nghttp3=/path/to/nghttp3
     % make
     % make install

Build curl (with CMake):

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % PKG_CONFIG_PATH=/path/to/wolfssl/lib/pkgconfig:/path/to/ngtcp2/lib/pkgconfig:/path/to/nghttp3/lib/pkgconfig cmake -B bld -DCURL_USE_WOLFSSL=ON -DUSE_NGTCP2=ON
     % cmake --build bld

# quiche version

quiche support is **EXPERIMENTAL**

Since the quiche build manages its dependencies, curl can be built against the
latest version. You are *probably* able to build against their main branch,
but in case of problems, we recommend their latest release tag.

## Build

Build quiche and BoringSSL:

     % git clone --recursive -b 0.22.0 https://github.com/cloudflare/quiche
     % cd quiche
     % cargo build --package quiche --release --features ffi,pkg-config-meta,qlog
     % ln -s libquiche.so target/release/libquiche.so.0
     % mkdir quiche/deps/boringssl/src/lib
     % ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) quiche/deps/boringssl/src/lib/

Build curl:

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure LDFLAGS="-Wl,-rpath,$PWD/../quiche/target/release" --with-openssl=$PWD/../quiche/quiche/deps/boringssl/src --with-quiche=$PWD/../quiche/target/release
     % make
     % make install

If `make install` results in `Permission denied` error, you need to prepend
it with `sudo`.

# `--http3`

Use only HTTP/3:

     % curl --http3-only https://example.org:4433/

Use HTTP/3 with fallback to HTTP/2 or HTTP/1.1 (see "HTTPS eyeballing" below):

     % curl --http3 https://example.org:4433/

Upgrade via Alt-Svc:

     % curl --alt-svc altsvc.cache https://curl.se/

See this [list of public HTTP/3 servers](https://bagder.github.io/HTTP3-test/)

### HTTPS eyeballing

With option `--http3` curl attempts earlier HTTP versions as well should the
connect attempt via HTTP/3 fail "fast enough". This strategy is similar
to IPv4/6 happy eyeballing where the alternate address family is used in
parallel after a short delay.

The IPv4/6 eyeballing has a default of 200ms and you may override that via
`--happy-eyeballs-timeout-ms value`. Since HTTP/3 is still relatively new, we
decided to use this timeout also for the HTTP eyeballing - with a slight
twist.

The `happy-eyeballs-timeout-ms` value is the **hard** timeout, meaning after
that time expired, a TLS connection is opened in addition to negotiate HTTP/2
or HTTP/1.1. At half of that value - currently - is the **soft** timeout. The
soft timeout fires, when there has been **no data at all** seen from the
server on the HTTP/3 connection.

Without you specifying anything, the hard timeout is 200ms and the soft is
100ms:

* Ideally, the whole QUIC handshake happens and curl has an HTTP/3 connection
  in less than 100ms.
* When QUIC is not supported (or UDP does not work for this network path), no
  reply is seen and the HTTP/2 TLS+TCP connection starts 100ms later.
* In the worst case, UDP replies start before 100ms, but drag on. This starts
  the TLS+TCP connection after 200ms.
* When the QUIC handshake fails, the TLS+TCP connection is attempted right
  away. For example, when the QUIC server presents the wrong certificate.

The whole transfer only fails, when **both** QUIC and TLS+TCP fail to
handshake or time out.

Note that all this happens in addition to IP version happy eyeballing. If the
name resolution for the server gives more than one IP address, curl tries all
those until one succeeds - as with all other protocols. If those IP addresses
contain both IPv6 and IPv4, those attempts happen, delayed, in parallel (the
actual eyeballing).

## Known Bugs

Check out the [list of known HTTP3 bugs](https://curl.se/docs/knownbugs.html#HTTP3).

# HTTP/3 Test server

This is not advice on how to run anything in production. This is for
development and experimenting.

## Prerequisite(s)

An existing local HTTP/1.1 server that hosts files. Preferably also a few huge
ones. You can easily create huge local files like `truncate -s=8G 8GB` - they
are huge but do not occupy that much space on disk since they are big holes.

In a Debian setup you can install apache2. It runs on port 80 and has a
document root in `/var/www/html`. Download the 8GB file from apache with `curl
localhost/8GB -o dev/null`

In this description we setup and run an HTTP/3 reverse-proxy in front of the
HTTP/1 server.

## Setup

You can select either or both of these server solutions.

### nghttpx

Get, build and install quictls, nghttp3 and ngtcp2 as described
above.

Get, build and install nghttp2:

     % git clone https://github.com/nghttp2/nghttp2
     % cd nghttp2
     % autoreconf -fi
     % PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/home/daniel/build-quictls/lib/pkgconfig:/home/daniel/build-nghttp3/lib/pkgconfig:/home/daniel/build-ngtcp2/lib/pkgconfig LDFLAGS=-L/home/daniel/build-quictls/lib CFLAGS=-I/home/daniel/build-quictls/include ./configure --enable-maintainer-mode --prefix=/home/daniel/build-nghttp2 --disable-shared --enable-app --enable-http3 --without-jemalloc --without-libxml2 --without-systemd
     % make && make install

Run the local h3 server on port 9443, make it proxy all traffic through to
HTTP/1 on localhost port 80. For local toying, we can use the test cert that
exists in curl's test dir.

     % CERT=/path/to/stunnel.pem
     % $HOME/bin/nghttpx $CERT $CERT --backend=localhost,80 \
      --frontend="localhost,9443;quic"

### Caddy

[Install Caddy](https://caddyserver.com/docs/install). For easiest use, the
binary should be either in your PATH or your current directory.

Create a `Caddyfile` with the following content:
~~~
localhost:7443 {
  respond "Hello, world! you are using {http.request.proto}"
}
~~~

Then run Caddy:

     % ./caddy start

Making requests to `https://localhost:7443` should tell you which protocol is
being used.

You can change the hard-coded response to something more useful by replacing
`respond` with `reverse_proxy` or `file_server`, for example: `reverse_proxy
localhost:80`
