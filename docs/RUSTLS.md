<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rustls

[Rustls is a TLS backend written in Rust](https://docs.rs/rustls/). curl can
be built to use it as an alternative to OpenSSL or other TLS backends. We use
the [rustls-ffi C bindings](https://github.com/rustls/rustls-ffi/). This
version of curl is compatible with `rustls-ffi` v0.15.x.

## Getting rustls-ffi

To build `curl` with `rustls` support you need to have `rustls-ffi` available first.
There are three options for this:

1. Install it from your package manager, if available.
2. Download pre-built binaries.
3. Build it from source.

### Installing rustls-ffi from a package manager

See the [rustls-ffi README] for packaging status. Availability and details for installation
differ between distributions.

Once installed, build `curl` using `--with-rustls`.

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls
    % make

[rustls-ffi README]: https://github.com/rustls/rustls-ffi?tab=readme-ov-file

### Downloading pre-built rustls-ffi binaries

Pre-built binaries are available on the [releases page] on GitHub for releases since 0.15.0.
Download the appropriate archive for your platform and extract it to a directory of your choice
(e.g. `${HOME}/rustls-ffi-built`).

Once downloaded, build `curl` using `--with-rustls` and the path to the extracted binaries.

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

[releases page]: https://github.com/rustls/rustls-ffi/releases

### Building rustls-ffi from source

Building `rustls-ffi` from source requires both a rust compiler, and the [cargo-c] cargo plugin.

To install a Rust compiler, use [rustup] or your package manager to install
the **1.73+** or newer toolchain.

To install `cargo-c`, use your [package manager][cargo-c pkg], download
[a pre-built archive][cargo-c prebuilt], or build it from source with `cargo install cargo-c`.

Next, check out, build, and install the appropriate version of `rustls-ffi` using `cargo`:

    % git clone https://github.com/rustls/rustls-ffi -b v0.15.0
    % cd rustls-ffi
    % cargo capi install --release --prefix=${HOME}/rustls-ffi-built

Now configure and build `curl` using `--with-rustls`:

    % git clone https://github.com/curl/curl
    % cd curl
    % autoreconf -fi
    % ./configure --with-rustls=${HOME}/rustls-ffi-built
    % make

See the [rustls-ffi README][cryptography provider] for more information on cryptography providers and
their build/platform requirements.

[cargo-c]: https://github.com/lu-zero/cargo-c
[rustup]: https://rustup.rs/
[cargo-c pkg]: https://github.com/lu-zero/cargo-c?tab=readme-ov-file#availability
[cargo-c prebuilt]: https://github.com/lu-zero/cargo-c/releases
[cryptography provider]: https://github.com/cpu/rustls-ffi?tab=readme-ov-file#cryptography-provider
