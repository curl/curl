HTTP/2 with curl
================

[HTTP/2 Spec](https://www.rfc-editor.org/rfc/rfc7540.txt)
[http2 explained](https://daniel.haxx.se/http2/)

Build prerequisites
-------------------
  - nghttp2
  - OpenSSL, libressl, BoringSSL, NSS, GnuTLS, mbedTLS, wolfSSL or Schannel
    with a new enough version.

[nghttp2](https://nghttp2.org/)
-------------------------------

libcurl uses this 3rd party library for the low level protocol handling
parts. The reason for this is that HTTP/2 is much more complex at that layer
than HTTP/1.1 (which we implement on our own) and that nghttp2 is an already
existing and well functional library.

We require at least version 1.12.0.

Over an http:// URL
-------------------

If `CURLOPT_HTTP_VERSION` is set to `CURL_HTTP_VERSION_2_0`, libcurl will
include an upgrade header in the initial request to the host to allow
upgrading to HTTP/2.

Possibly we can later introduce an option that will cause libcurl to fail if
not possible to upgrade. Possibly we introduce an option that makes libcurl
use HTTP/2 at once over http://

Over an https:// URL
--------------------

If `CURLOPT_HTTP_VERSION` is set to `CURL_HTTP_VERSION_2_0`, libcurl will use
ALPN (or NPN) to negotiate which protocol to continue with. Possibly introduce
an option that will cause libcurl to fail if not possible to use HTTP/2.

`CURL_HTTP_VERSION_2TLS` was added in 7.47.0 as a way to ask libcurl to prefer
HTTP/2 for HTTPS but stick to 1.1 by default for plain old HTTP connections.

ALPN is the TLS extension that HTTP/2 is expected to use. The NPN extension is
for a similar purpose, was made prior to ALPN and is used for SPDY so early
HTTP/2 servers are implemented using NPN before ALPN support is widespread.

`CURLOPT_SSL_ENABLE_ALPN` and `CURLOPT_SSL_ENABLE_NPN` are offered to allow
applications to explicitly disable ALPN or NPN.

SSL libs
--------

The challenge is the ALPN and NPN support and all our different SSL
backends. You may need a fairly updated SSL library version for it to provide
the necessary TLS features. Right now we support:

  - OpenSSL:          ALPN and NPN
  - libressl:         ALPN and NPN
  - BoringSSL:        ALPN and NPN
  - NSS:              ALPN and NPN
  - GnuTLS:           ALPN
  - mbedTLS:          ALPN
  - Schannel:         ALPN
  - wolfSSL:          ALPN
  - Secure Transport: ALPN

Multiplexing
------------

Starting in 7.43.0, libcurl fully supports HTTP/2 multiplexing, which is the
term for doing multiple independent transfers over the same physical TCP
connection.

To take advantage of multiplexing, you need to use the multi interface and set
`CURLMOPT_PIPELINING` to `CURLPIPE_MULTIPLEX`. With that bit set, libcurl will
attempt to re-use existing HTTP/2 connections and just add a new stream over
that when doing subsequent parallel requests.

While libcurl sets up a connection to a HTTP server there is a period during
which it doesn't know if it can pipeline or do multiplexing and if you add new
transfers in that period, libcurl will default to start new connections for
those transfers. With the new option `CURLOPT_PIPEWAIT` (added in 7.43.0), you
can ask that a transfer should rather wait and see in case there's a
connection for the same host in progress that might end up being possible to
multiplex on. It favours keeping the number of connections low to the cost of
slightly longer time to first byte transferred.

Applications
------------

We hide HTTP/2's binary nature and convert received HTTP/2 traffic to headers
in HTTP 1.1 style. This allows applications to work unmodified.

curl tool
---------

curl offers the `--http2` command line option to enable use of HTTP/2.

curl offers the `--http2-prior-knowledge` command line option to enable use of
HTTP/2 without HTTP/1.1 Upgrade.

Since 7.47.0, the curl tool enables HTTP/2 by default for HTTPS connections.

curl tool limitations
---------------------

The command line tool also doesn't support HTTP/2 server push for the same
reason it doesn't do multiplexing: it needs to use the multi interface for
that so that multiplexing is supported.

HTTP Alternative Services
-------------------------

Alt-Svc is an extension with a corresponding frame (ALTSVC) in HTTP/2 that
tells the client about an alternative "route" to the same content for the same
origin server that you get the response from. A browser or long-living client
can use that hint to create a new connection asynchronously.  For libcurl, we
may introduce a way to bring such clues to the application and/or let a
subsequent request use the alternate route automatically.

[Detailed in RFC 7838](https://tools.ietf.org/html/rfc7838)
