# tiny-curl

tiny-curl is a patch set on top of the regular curl source tree to make the
built libcurl smaller and leaner, at the price of less features.

The goal is to provide libcurl plus wolfSSL within 100K on a 32bit
architecture.

On x86-64 Linux, the library size is smaller than 25% the size of the
"regular" distributed libcurl version shipped on Debian.

## Version

This is tiny-curl 7.72.0. It identifies itself as libcurl 7.72.0.

## Features

tiny-curl maintains the libcurl ABI and API. All regular functions and defines
are present. For functions where functionality has been removed for the sake of
reducing footprint, libcurl will instead return errors.

The focus on tiny-curl is to maintain HTTPS GET support and all other strong
sides of libcurl that aren't specifically disabled.

## Removed Features

By default, tiny-curl builds with these features disabled:

- No protocols except HTTP(S) are supported
- No cookie support
- No date parsing
- No alt-svc support
- No HTTP authentication
- No DNS-over-HTTPS
- No .netrc parsing
- No HTTP multi-part formposts
- No shuffled DNS support
- No built-in progress meter
- No IDN support
- No HTTP compression
- No socketpair support
- Only HTTP/1 and HTTP/0.9 support

All of these features and protocols can be enabled individually at build-time,
should a user like that. At the expense of a larger footprint of course.

## Portability

In addition to all the platforms the regular curl builds and runs on,
tiny-curl has been succesfully run on:

 - FreeRTOS
 - Micrium OS

## License

The tiny-curl patch set is licensed under the GPLv3 license. See docs/GPLv3.txt
for details.

## Tiny-curl Linux

Example build script for tiny-curl on Linux:

    #!/bin/sh
    export CFLAGS="-Os -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -flto"
    export LDFLAGS="-Wl,-s -Wl,-Bsymbolic -Wl,--gc-sections"
    ./configure \
    --disable-cookies \
    --disable-crypto-auth \
    --disable-dict \
    --disable-file \
    --disable-ftp \
    --disable-gopher \
    --disable-imap \
    --disable-ldap \
    --disable-pop3 \
    --disable-proxy \
    --disable-rtmp \
    --disable-rtsp \
    --disable-scp \
    --disable-sftp \
    --disable-smtp \
    --disable-telnet \
    --disable-tftp \
    --disable-unix-sockets \
    --disable-verbose \
    --disable-versioned-symbols \
    --disable-http-auth \
    --disable-doh \
    --disable-mime \
    --disable-dateparse \
    --disable-netrc \
    --disable-dnsshuffle \
    --disable-progress-meter \
    --enable-maintainer-mode \
    --enable-werror \
    --without-brotli \
    --without-gssapi \
    --without-libidn2 \
    --without-libmetalink \
    --without-libpsl \
    --without-librtmp \
    --without-libssh2 \
    --without-nghttp2 \
    --without-ntlm-auth \
    --without-ssl \
    --without-zlib \
    --with-wolfssl=/home/daniel/build-wolfssl
