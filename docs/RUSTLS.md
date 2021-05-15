# Rustls

[Rustls is a TLS backend written in Rust.](https://docs.rs/rustls/). Curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [crustls C bindings](https://github.com/abetterinternet/crustls/). This
version of curl depends on version v0.6.0 of crustls.

# Building with rustls

First, [install Rust](https://rustup.rs/).

Next, check out, build, and install the appropriate version of crustls:

    % cargo install cbindgen
    % git clone https://github.com/abetterinternet/crustls/ -b v0.6.0
    % cd crustls
    % make
    % make DESTDIR=${HOME}/crustls-built/ install

Now configure and build curl with rustls:

    % git clone https://github.com/curl/curl
    % cd curl
    % ./buildconf
    % ./configure --without-ssl --with-rustls=${HOME}/crustls-built
    % make
