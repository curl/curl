# Hyper

Hyper is a separate HTTP library written in Rust. curl can be told to use this
library as a backend to deal with HTTP.

## Experimental!

Hyper support in curl is considered **EXPERIMENTAL** until further notice. It
needs to be explicitly enabled at build-time.

Further development and tweaking of the Hyper backend support in curl will
happen in in the master branch using pull-requests, just like ordinary
changes.

## Hyper version

The C API for Hyper is brand new and under development. This description
assumes that you get and build that C API off [the branch in Hyper's git
repository](https://github.com/hyperium/hyper/tree/hyper-capi).

## build curl with hyper

Build hyper and enable the C API:

     % git clone -b hyper-capi https://github.com/hyperium/hyper
     % cd hyper
     % cargo build --no-default-features --features ffi

Build curl to use hyper's C API:

     % git clone https://github.com/curl/curl
     % cd curl
     % ./buildconf
     % ./configure --with-hyper=<hyper dir>
     % make

# using Hyper internally

Hyper is a low level HTTP transport library. curl itself provides all HTTP
headers and Hyper provides all received headers back to curl.

Therefore, msost of the "header logic" in curl as in responding to and acting
on specific input and output headers are done the same way in curl code.

The API in Hyper delivers received HTTP headers as (cleaned up) name=value
pairs, making it impossible for curl to know the exact byte representation
over the wire with Hyper.
