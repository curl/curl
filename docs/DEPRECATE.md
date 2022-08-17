# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## NSS

We remove support for building curl with the NSS TLS library in August 2023.

- There are very few users left who use curl+NSS
- NSS has very few users outside of curl as well (primarily Firefox)
- NSS is harder than ever to find documentation for
- NSS was always "best" used with Red Hat Linux when they provided additional
  features on top of the regular NSS that is not shipped by the vanilla library

Starting in 7.82.0, building curl to use NSS configure requires the additional
flag --with-nss-deprecated in an attempt to highlight these plans.

## NPN

We make selecting NPN a no-op starting in August 2022.

**Next Protocol Negotiation** is a TLS extension that was created and used for
agreeing to use the SPDY protocol (the precursor to HTTP/2) for HTTPS. In the
early days of HTTP/2, before the spec was finalized and shipped, the protocol
could be enabled using this extension with some servers.

curl supports the NPN extension with some TLS backends since then, with a
command line option `--npn` and in libcurl with `CURLOPT_SSL_ENABLE_NPN`.

HTTP/2 proper is made to use the ALPN (Application-Layer Protocol Negotiation)
extension and the NPN extension has no purposes anymore. The HTTP/2 spec was
published in May 2015.

Today, use of NPN in the wild should be extremely rare and most likely totally
extinct. Chrome removed NPN support in Chrome 51, shipped in
June 2016. Removed in Firefox 53, April 2017.

## past removals

 - Pipelining
 - axTLS
 - PolarSSL
