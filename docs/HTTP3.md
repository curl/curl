# HTTP3 (and QUIC)

## Resources

[HTTP/3 Explained](https://daniel.haxx.se/http3-explained/) - the online free
book describing the protocols involved.

[QUIC implementation](https://github.com/curl/curl/wiki/QUIC-implementation) -
the wiki page describing the plan for how to support QUIC and HTTP/3 in curl
and libcurl.

[quicwg.org](https://quicwg.org/) - home of the official protocol drafts

## QUIC libraries

QUIC libraries we're experiementing with:

[ngtcp2](https://github.com/ngtcp2/ngtcp2)

[quiche](https://github.com/cloudflare/quiche)

## Experimental!

HTTP/3 and QUIC support in curl is not yet working and this is early days.
Consider all QUIC and HTTP/3 code to be **EXPERIMENTAL** until further notice.

curl does not have HTTP/3 support (yet).

The bleeding edge QUIC work is done in the dedicated
[QUIC](https://github.com/curl/curl/tree/QUIC) branch, but the plan is to
merge as often as possible from there to master. All QUIC related code will
remain being build-time conditionally enabled.

# ngtcp2 version

## Build

1. clone ngtcp2 from git (the draft-17 branch)
2. build and install ngtcp2's custom OpenSSL version (the quic-draft-17 branch)
3. build and install ngtcp2 according to its instructions
4. configure curl with ngtcp2 support: `./configure --with-ngtcp2=<install prefix>`
5. build curl "normally"

## Running

Make sure the custom OpenSSL library is the one used at run-time, as otherwise
you'll just get ld.so linker errors.

## Invoke from command line

    curl --http3-direct https://nghttp2.org:8443/

# quiche version

## build

Build BoringSSL (it needs to be built manually so it can be reused with curl):

     % mkdir -p quiche/deps/boringssl/build
     % cd quiche/deps/boringssl/build
     % cmake -DCMAKE_POSITION_INDEPENDENT_CODE=on ..
     % make -j`nproc`
     % cd ..
     % mkdir .openssl/lib -p
     % cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib
     % ln -s $PWD/include .openssl

Build quiche:

     % cd ../..
     % QUICHE_BSSL_PATH=$PWD/deps/boringssl cargo build --release

Clone and build curl:

     % cd ..
     % git clone https://github.com/curl/curl
     % ./buildconf
     % ./configure --with-ssl=$PWD/../quiche/deps/boringssl/.openssl --with-quiche=$PWD/../quiche --enable-debug
     % make -j`nproc`

## Running

Make an HTTP/1.1 request to a QUIC server:

     % src/curl --http3-direct https://cloudflare-quic.com/
