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

## Experimental!

HTTP/3 and QUIC support in curl is considered **EXPERIMENTAL** until further
notice. It needs to be enabled at build-time.

Further development and tweaking of the HTTP/3 support in curl will happen in
in the master branch using pull-requests, just like ordinary changes.

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

For OpenSSL 3.0.0 or later builds on Linux for x86_64 architecture, substitute all occurances of "/lib" with "/lib64"

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
     % cargo build --release --features ffi,pkg-config-meta,qlog
     % mkdir deps/boringssl/src/lib
     % ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) deps/boringssl/src/lib/

Build curl:

     % cd ..
     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure LDFLAGS="-Wl,-rpath,$PWD/../quiche/target/release" --with-openssl=$PWD/../quiche/deps/boringssl/src --with-quiche=$PWD/../quiche/target/release
     % make
     % make install

 If `make install` results in `Permission denied` error, you will need to prepend it with `sudo`.

## Run

Use HTTP/3 directly:

    curl --http3 https://nghttp2.org:4433/

Upgrade via Alt-Svc:

    curl --alt-svc altsvc.cache https://quic.aiortc.org/

See this [list of public HTTP/3 servers](https://bagder.github.io/HTTP3-test/)
