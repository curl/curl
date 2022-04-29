# HTTP3 (and QUIC)

## Resources

[HTTP/3 Explained](https://http3-explained.haxx.se/en/) - the online free
book describing the protocols involved.

[QUIC implementation](https://github.com/curl/curl/wiki/QUIC-implementation) -
the wiki page describing the plan for how to support QUIC and HTTP/3 in curl
and libcurl.

[quicwg.org](https://quicwg.org/) - home of the official protocol drafts

## QUIC libraries

QUIC libraries we are experimenting with:

[ngtcp2](https://github.com/ngtcp2/ngtcp2)

[quiche](https://github.com/cloudflare/quiche)

[msquic](https://github.com/microsoft/msquic) & [msh3](https://github.com/nibanks/msh3)

## Experimental

HTTP/3 and QUIC support in curl is considered **EXPERIMENTAL** until further
notice. It needs to be enabled at build-time.

Further development and tweaking of the HTTP/3 support in curl will happen in
the master branch using pull-requests, just like ordinary changes.

# ngtcp2 version

## Build with OpenSSL

Build (patched) OpenSSL

     % git clone --depth 1 -b openssl-3.0.0+quic https://github.com/quictls/openssl
     % cd openssl
     % ./config enable-tls1_3 --prefix=<somewhere1>
     % make
     % make install

Build nghttp3

     % cd ..
     % git clone https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % autoreconf -fi
     % ./configure --prefix=<somewhere2> --enable-lib-only
     % make
     % make install

Build ngtcp2

     % cd ..
     % git clone https://github.com/ngtcp2/ngtcp2
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
     % git clone https://github.com/ngtcp2/nghttp3
     % cd nghttp3
     % autoreconf -fi
     % ./configure --prefix=<somewhere2> --enable-lib-only
     % make
     % make install

Build ngtcp2

     % cd ..
     % git clone https://github.com/ngtcp2/ngtcp2
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
     % ./configure --without-openssl --with-gnutls=<somewhere1> --with-nghttp3=<somewhere2> --with-ngtcp2=<somewhere3>
     % make
     % make install

# quiche version

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

## Build Linux (with quictls fork of OpenSSL)

Build msh3:

     % git clone --depth 1 --recursive https://github.com/nibanks/msh3
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

     % git clone --depth 1 --recursive https://github.com/nibanks/msh3
     % cd msh3 && mkdir build && cd build
     % cmake -G 'Visual Studio 17 2022' -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
     % cmake --build . --config Release
     % cmake --install . --config Release

**Note** - On Windows, Schannel will be used for TLS support by default. If
you with to use (the quictls fork of) OpenSSL, specify the `-DQUIC_TLS=openssl`
option to the generate command above. Also note that OpenSSL brings with it an
additional set of build dependencies not specified here.

Build curl (in [Visual Studio Command prompt](../winbuild/README.md#open-a-command-prompt)):

     % git clone https://github.com/curl/curl
     % cd curl/winbuild
     % nmake /f Makefile.vc mode=dll WITH_MSH3=dll MSH3_PATH="C:/Program Files/msh3" MACHINE=x64

**Note** - If you encounter a build error with `tool_hugehelp.c` being missing,
rename `tool_hugehelp.c.cvs` in the same directory to `tool_hugehelp.c` and
then run `nmake` again.

Run in the `C:/Program Files/msh3/lib` directory, copy `curl.exe` to that
directory, or copy `msquic.dll` and `msh3.dll` from that directory to the
`curl.exe` directory. For example:

     % C:\Program Files\msh3\lib> F:\curl\builds\libcurl-vc-x64-release-dll-ipv6-sspi-schannel-msh3\bin\curl.exe --http3 https://www.google.com

# `--http3`

Use HTTP/3 directly:

    curl --http3 https://nghttp2.org:4433/

Upgrade via Alt-Svc:

    curl --alt-svc altsvc.cache https://quic.aiortc.org/

See this [list of public HTTP/3 servers](https://bagder.github.io/HTTP3-test/)

## Known Bugs

Check out the [list of known HTTP3 bugs](https://curl.se/docs/knownbugs.html#HTTP3).

# HTTP/3 Test server

This is not advice on how to run anything in production. This is for
development and experimenting.

## Prerequisite(s)

An existing local HTTP/1.1 server that hosts files. Preferably also a few huge
ones.  You can easily create huge local files like `truncate -s=8G 8GB` - they
are huge but do not occupy that much space on disk since they are just big
holes.

In my Debian setup I just installed **apache2**. It runs on port 80 and has a
document root in `/var/www/html`. I can get the 8GB file from it with `curl
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

[Install caddy](https://caddyserver.com/docs/install), you can even put the
single binary in a separate directory if you prefer.

In the same directory you put caddy, create a `Caddyfile` with the following
content to run an HTTP/3 reverse-proxy on port 7443:
~~~
{
    auto_https disable_redirects
	servers :7443 {
		protocol {
			experimental_http3
		}
	}
}

localhost:7443 {
	reverse_proxy localhost:80
}
~~~

Then run caddy:

    ./caddy start
