# Rustls

[Rustls is a TLS backend written in Rust](https://docs.rs/rustls/). Curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [rustls-ffi C bindings](https://github.com/rustls/rustls-ffi/). This
version of curl depends on version v0.10.0 of rustls-ffi.

# Building with rustls

First, [install Rust](https://rustup.rs/).

Next, check out, build, and install the appropriate version of rustls-ffi:

    % cargo install cbindgen
    % git clone https://github.com/rustls/rustls-ffi -b v0.10.0
    % cd rustls-ffi
    % make
    % make DESTDIR=${HOME}/rustls-ffi-built/ install

Now configure and build curl with rustls:

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make
