# Hyper

Hyper is a separate HTTP library written in Rust. curl can be told to use this
library as a backend to deal with HTTP.

## Experimental!

Hyper support in curl is considered **EXPERIMENTAL** until further notice. It
needs to be explicitly enabled at build-time.

Further development and tweaking of the Hyper backend support in curl will
happen in the master branch using pull-requests, just like ordinary
changes.

## Hyper version

The C API for Hyper is brand new and is still under development.

## build curl with hyper

Since March 3 2022, hyper needs the nightly rustc to build, which you may need
to install first with:

     % rustup toolchain install nightly

Then build hyper and enable its C API like this:

     % git clone https://github.com/hyperium/hyper
     % cd hyper
     % RUSTFLAGS="--cfg hyper_unstable_ffi" cargo +nightly rustc --features client,http1,http2,ffi -Z unstable-options --crate-type cdylib

Build curl to use hyper's C API:

     % git clone https://github.com/curl/curl
     % cd curl
     % autoreconf -fi
     % ./configure --with-hyper=<hyper dir>
     % make

# using Hyper internally

Hyper is a low level HTTP transport library. curl itself provides all HTTP
headers and Hyper provides all received headers back to curl.

Therefore, most of the "header logic" in curl as in responding to and acting
on specific input and output headers are done the same way in curl code.

The API in Hyper delivers received HTTP headers as (cleaned up) name=value
pairs, making it impossible for curl to know the exact byte representation
over the wire with Hyper.

## Limitations

The hyper backend does not support

- `CURLOPT_IGNORE_CONTENT_LENGTH`
- `--raw` and disabling `CURLOPT_HTTP_TRANSFER_DECODING`
- RTSP
- hyper is much stricter about what HTTP header contents it allows
- HTTP/0.9
- HTTP/2 upgrade using HTTP:// URLs. Aka 'h2c'

## Remaining issues

This backend is still not feature complete with the native backend. Areas that
still need attention and verification include:

- multiplexed HTTP/2
- h2 Upgrade:
- pausing transfers
- receiving HTTP/1 trailers
- sending HTTP/1 trailers

