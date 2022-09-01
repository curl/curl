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

## past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
