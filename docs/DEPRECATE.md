# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## Support for systems without 64 bit data types

curl will *require* support for a 64 bit data type (like `long long` or an
alternative) to build. These days, few systems are used where no such type is
around, so it is increasingly unnecessary to spend effort and time on
maintaining this support. Also, supporting 32 bit values for some of those
fields is complicated and hard to test.

Adding this requirement will make the code simpler, easier to maintain and the
test coverage better. It is a low price too, since virtually no users are
still building curl on such systems.

`long long` was not a standard type until C99, but has been supported by C89
compilers since the 1990s.

Starting in 8.0.0 (March 2023), the plan is to drop support.

Starting in 7.86.0, building curl with configure requires the additional flag
`--with-n64-deprecated` if the `curl_off_t` type on your system is smaller
than 8 bytes, in an attempt to highlight these plans to affected users.

## NSS

We remove support for building curl with the NSS TLS library in August 2023.

- There are few users left who use curl+NSS
- NSS has few users outside of curl as well (primarily Firefox)
- NSS is harder than ever to find documentation for
- NSS was always "best" used with Red Hat Linux when they provided additional
  features on top of the regular NSS that is not shipped by the vanilla library

Starting in 7.82.0, building curl to use NSS configure requires the additional
flag `--with-nss-deprecated` in an attempt to highlight these plans.

## past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
