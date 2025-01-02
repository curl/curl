<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rustls

[Rustls is a TLS backend written in Rust](https://docs.rs/rustls/). curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [rustls-ffi C bindings](https://github.com/rustls/rustls-ffi/). This
version of curl depends on version v0.14.0 of rustls-ffi.

# Building with Rustls

First, [install Rust](https://rustup.rs/).

Next, check out, build, and install the appropriate version of rustls-ffi:

    % git clone https://github.com/rustls/rustls-ffi -b v0.14.0
    % cd rustls-ffi
    % make
    % make DESTDIR=${HOME}/rustls-ffi-built/ install

Now configure and build curl with Rustls:

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

See the [rustls-ffi README] for more information on cryptography providers and
their build/platform requirements.

[rustls-ffi README]: https://github.com/rustls/rustls-ffi/blob/main/README.md#cryptography-provide
