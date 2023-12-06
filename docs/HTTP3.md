# HTTP3 (and QUIC)

## Resources

[HTTP/3 Explained](https://http3-explained.haxx.se/en/) - the online free
book describing the protocols involved.

[quicwg.org](https://quicwg.org/) - home of the official protocol drafts

## QUIC libraries

QUIC libraries we are using:

[ngtcp2](https://github.com/ngtcp2/ngtcp2)

[quiche](https://github.com/cloudflare/quiche) - **EXPERIMENTAL**

[msh3](https://github.com/nibanks/msh3) (with [msquic](https://github.com/microsoft/msquic)) - **EXPERIMENTAL**

## Experimental

HTTP/3 support in curl is considered **EXPERIMENTAL** until further notice
when built to use *quiche* or *msh3*. Only the *ngtcp2* backend is not
experimental.

Further development and tweaking of the HTTP/3 support in curl will happen in
the master branch using pull-requests, just like ordinary changes.

To fix before we remove the experimental label:

 - the used QUIC library needs to consider itself non-beta
 - it's fine to "leave" individual backends as experimental if necessary

# ngtcp2 version

Building curl with ngtcp2 involves 3 components: `ngtcp2` itself, `nghttp3` and a QUIC supporting TLS library. The supported TLS libraries are covered below.

 * `ngtcp2`: v1.1.0
 * `nghttp3`: v1.1.0

## Build with quictls

OpenSSL does not offer the required APIs for building a QUIC client. You need
to use a TLS library that has such APIs and that works with *ngtcp2*.

Build quictls

     % git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl
     % cd openssl
     % ./config enable-tls1_3 --prefix=<somewhere1>
     % make
     % make install

Build nghttp3

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % autoreconf -fi
     % ./configure --prefix=<somewhere2> --enable-lib-only
     % make
     % make install

Build ngtcp2

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=<somewhere1>/lib/pkgconfig:<somewhere2>/lib/pkgconfig LDFLAGS="-Wl,-rpath,<somewhere1>/lib" --prefix=<somewhere3> --enable-lib-only
     % make
     % make install

Build curl

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % LDFLAGS="-Wl,-rpath,<somewhere1>/lib" ./configure --with-openssl=<somewhere1> --with-nghttp3=<somewhere2> --with-ngtcp2=<somewhere3>
     % make
     % make install

For OpenSSL 3.0.0 or later builds on Linux for x86_64 architecture, substitute all occurrences of "/lib" with "/lib64"

## Build with GnuTLS

Build GnuTLS

     % git clone --depth 1 https://gitlab.com/gnutls/gnutls.git
     % cd gnutls
     % ./bootstrap
     % ./configure --prefix=<somewhere1>
     % make
     % make install

Build nghttp3

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % autoreconf -fi
     % ./configure --prefix=<somewhere2> --enable-lib-only
     % make
     % make install

Build ngtcp2

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=<somewhere1>/lib/pkgconfig:<somewhere2>/lib/pkgconfig LDFLAGS="-Wl,-rpath,<somewhere1>/lib" --prefix=<somewhere3> --enable-lib-only --with-gnutls
     % make
     % make install

Build curl

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure --with-gnutls=<somewhere1> --with-nghttp3=<somewhere2> --with-ngtcp2=<somewhere3>
     % make
     % make install

## Build with wolfSSL

Build wolfSSL

     % git clone https://github.com/wolfSSL/wolfssl.git
     % cd wolfssl
     % autoreconf -fi
     % ./configure --prefix=<somewhere1> --enable-quic --enable-session-ticket --enable-earlydata --enable-psk --enable-harden --enable-altcertchains
     % make
     % make install

Build nghttp3

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % autoreconf -fi
     % ./configure --prefix=<somewhere2> --enable-lib-only
     % make
     % make install

Build ngtcp2

     % cd ..
     % git clone -b v1.1.0 https://github.com/ngtcp2/ngtcp2
     % cd ngtcp2
     % autoreconf -fi
     % ./configure PKG_CONFIG_PATH=<somewhere1>/lib/pkgconfig:<somewhere2>/lib/pkgconfig LDFLAGS="-Wl,-rpath,<somewhere1>/lib" --prefix=<somewhere3> --enable-lib-only --with-wolfssl
     % make
     % make install

Build curl

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure --with-wolfssl=<somewhere1> --with-nghttp3=<somewhere2> --with-ngtcp2=<somewhere3>
     % make
     % make install

# quiche version

quiche support is **EXPERIMENTAL**

Since the quiche build manages its dependencies, curl can be built against the latest version. You are *probably* able to build against their main branch, but in case of problems, we recommend their latest release tag.

## build

Build quiche and BoringSSL:

     % git clone --recursive https://github.com/cloudflare/quiche
     % cd quiche
     % cargo build --package quiche --release --features ffi,pkg-config-meta,qlog
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

 If `make install` results in `Permission denied` error, you will need to prepend it with `sudo`.

# msh3 (msquic) version

**Note**: The msquic HTTP/3 backend is immature and is not properly functional
one as of September 2023. Feel free to help us test it and improve it, but
there is no point in filing bugs about it just yet.

msh3 support is **EXPERIMENTAL**

## Build Linux (with quictls fork of OpenSSL)

Build msh3:

     % git clone -b v0.6.0 --depth 1 --recursive https://github.com/nibanks/msh3
     % cd msh3 && mkdir build && cd build
     % cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
     % cmake --build .
     % cmake --install .

Build curl:

     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure LDFLAGS="-Wl,-rpath,/usr/local/lib" --with-msh3=/usr/local --with-openssl
     % make
     % make install

Run from `/usr/local/bin/curl`.

## Build Windows

Build msh3:

     % git clone -b v0.6.0 --depth 1 --recursive https://github.com/nibanks/msh3
     % cd msh3 && mkdir build && cd build
     % cmake -G 'Visual Studio 17 2022' -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
     % cmake --build . --config Release
     % cmake --install . --config Release

**Note** - On Windows, Schannel will be used for TLS support by default. If
you with to use (the quictls fork of) OpenSSL, specify the
`-DQUIC_TLS=openssl` option to the generate command above. Also note that
OpenSSL brings with it an additional set of build dependencies not specified
here.

Build curl (in [Visual Studio Command
prompt](../winbuild/README.md#open-a-command-prompt)):

     % git clone https://github.com/curl/curl
     % cd curl/winbuild
     % nmake /f Makefile.vc mode=dll WITH_MSH3=dll MSH3_PATH="C:/Program Files/msh3" MACHINE=x64

**Note** - If you encounter a build error with `tool_hugehelp.c` being
missing, rename `tool_hugehelp.c.cvs` in the same directory to
`tool_hugehelp.c` and then run `nmake` again.

Run in the `C:/Program Files/msh3/lib` directory, copy `curl.exe` to that
directory, or copy `msquic.dll` and `msh3.dll` from that directory to the
`curl.exe` directory. For example:

     % C:\Program Files\msh3\lib> F:\curl\builds\libcurl-vc-x64-release-dll-ipv6-sspi-schannel-msh3\bin\curl.exe --http3 https://curl.se/

# `--http3`

Use only HTTP/3:

    curl --http3-only https://example.org:4433/

Use HTTP/3 with fallback to HTTP/2 or HTTP/1.1 (see "HTTPS eyeballing" below):

    curl --http3 https://example.org:4433/

Upgrade via Alt-Svc:

    curl --alt-svc altsvc.cache https://curl.se/

See this [list of public HTTP/3 servers](https://bagder.github.io/HTTP3-test/)

### HTTPS eyeballing

With option `--http3` curl will attempt earlier HTTP versions as well should
the connect attempt via HTTP/3 not succeed "fast enough". This strategy is
similar to IPv4/6 happy eyeballing where the alternate address family is used
in parallel after a short delay.

The IPv4/6 eyeballing has a default of 200ms and you may override that via
`--happy-eyeballs-timeout-ms value`. Since HTTP/3 is still relatively new, we
decided to use this timeout also for the HTTP eyeballing - with a slight
twist.

The `happy-eyeballs-timeout-ms` value is the **hard** timeout, meaning after
that time expired, a TLS connection is opened in addition to negotiate HTTP/2
or HTTP/1.1. At half of that value - currently - is the **soft** timeout. The
soft timeout fires, when there has been **no data at all** seen from the
server on the HTTP/3 connection.

So, without you specifying anything, the hard timeout is 200ms and the soft is 100ms:

 * Ideally, the whole QUIC handshake happens and curl has an HTTP/3 connection
   in less than 100ms.
 * When QUIC is not supported (or UDP does not work for this network path), no
   reply is seen and the HTTP/2 TLS+TCP connection starts 100ms later.
 * In the worst case, UDP replies start before 100ms, but drag on. This will
   start the TLS+TCP connection after 200ms.
 * When the QUIC handshake fails, the TLS+TCP connection is attempted right
   away. For example, when the QUIC server presents the wrong certificate.

The whole transfer only fails, when **both** QUIC and TLS+TCP fail to
handshake or time out.

Note that all this happens in addition to IP version happy eyeballing. If the
name resolution for the server gives more than one IP address, curl will try
all those until one succeeds - just as with all other protocols. And if those
IP addresses contain both IPv6 and IPv4, those attempts will happen, delayed,
in parallel (the actual eyeballing).

## Known Bugs

Check out the [list of known HTTP3 bugs](https://curl.se/docs/knownbugs.html#HTTP3).

# HTTP/3 Test server

This is not advice on how to run anything in production. This is for
development and experimenting.

## Prerequisite(s)

An existing local HTTP/1.1 server that hosts files. Preferably also a few huge
ones. You can easily create huge local files like `truncate -s=8G 8GB` - they
are huge but do not occupy that much space on disk since they are just big
holes.

In a Debian setup you can install **apache2**. It runs on port 80 and has a
document root in `/var/www/html`. Download the 8GB file from apache with `curl
localhost/8GB -o dev/null`

In this description we setup and run an HTTP/3 reverse-proxy in front of the
HTTP/1 server.

## Setup

You can select either or both of these server solutions.

### nghttpx

Get, build and install **quictls**, **nghttp3** and **ngtcp2** as described
above.

Get, build and install **nghttp2**:

    git clone https://github.com/nghttp2/nghttp2.git
    cd nghttp2
    autoreconf -fi
    PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/home/daniel/build-quictls/lib/pkgconfig:/home/daniel/build-nghttp3/lib/pkgconfig:/home/daniel/build-ngtcp2/lib/pkgconfig  LDFLAGS=-L/home/daniel/build-quictls/lib CFLAGS=-I/home/daniel/build-quictls/include ./configure --enable-maintainer-mode --prefix=/home/daniel/build-nghttp2 --disable-shared --enable-app --enable-http3 --without-jemalloc --without-libxml2 --without-systemd
    make && make install

Run the local h3 server on port 9443, make it proxy all traffic through to
HTTP/1 on localhost port 80. For local toying, we can just use the test cert
that exists in curl's test dir.

    CERT=$CURLSRC/tests/stunnel.pem
    $HOME/bin/nghttpx $CERT $CERT --backend=localhost,80 \
      --frontend="localhost,9443;quic"

### Caddy

[Install Caddy](https://caddyserver.com/docs/install). For easiest use, the binary
should be either in your PATH or your current directory.

Create a `Caddyfile` with the following content:
~~~
localhost:7443 {
  respond "Hello, world! you are using {http.request.proto}"
}
~~~

Then run Caddy:

    ./caddy start

Making requests to `https://localhost:7443` should tell you which protocol is being used.

You can change the hard-coded response to something more useful by replacing `respond`
with `reverse_proxy` or `file_server`, for example: `reverse_proxy localhost:80`
