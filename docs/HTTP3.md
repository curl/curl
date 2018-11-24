# HTTP3 (and QUIC)

## Resources

[HTTP/3 Explained](https://daniel.haxx.se/http3-explained/) - the online free
book describing the protocols involved.

[QUIC implementation](https://github.com/curl/curl/wiki/QUIC-implementation) -
the wiki page describing the plan for how to support QUIC and HTTP/3 in curl
and libcurl.

[quicwg.org](https://quicwg.org/) - home of the official protocol drafts

[ngtcp2](https://github.com/ngtcp2/ngtcp2) - the QUIC library we're basing
this work on.

## Experimental!

HTTP/3 and QUIC support in curl is not yet working and this is early days.
Consider all QUIC and HTTP/3 code to be **EXPERIMENTAL** until further notice.

ntcp2 does not have HTTP/3 support (yet).

## Code

The bleeding edge QUIC work is done in the dedicated
[ngtcp2](https://github.com/curl/curl/tree/ngtcp2) branch, but the plan is to
merge as often as possible from there to master. All QUIC related code will
remain being build-time conditionally enabled.

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
