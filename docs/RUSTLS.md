<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rustls

[Rustls is a TLS backend written in Rust](https://docs.rs/rustls/). Curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [rustls-ffi C bindings](https://github.com/rustls/rustls-ffi/). This
version of curl depends on version v0.13.0 of rustls-ffi.

# Building with Rustls

First, [install Rust](https://rustup.rs/).

Next, check out, build, and install the appropriate version of rustls-ffi:

    % git clone https://github.com/rustls/rustls-ffi -b v0.13.0
    % cd rustls-ffi
    % make
    % make DESTDIR=${HOME}/rustls-ffi-built/ install

Now configure and build curl with Rustls:

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

## Randomness

Every TLS libcurl curl supports - *except* Rustls - provides a function for
curl to extract cryptographically safe random numbers with.

When you build curl with Rustls, curl uses its own internal attempts to get a
decent random value:

1. Windows specific APIs
2. arc4random

If neither of those are present, then curl using Rustls falls back to **weak
pseudo-random values**, and thus weakening several curl authentication
implementations.
