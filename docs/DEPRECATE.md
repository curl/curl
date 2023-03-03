# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## NSS

We remove support for building curl with the NSS TLS library in August 2023.

- There are few users left who use curl+NSS
- NSS has few users outside of curl as well (primarily Firefox)
- NSS is harder than ever to find documentation for
- NSS was always "best" used with Red Hat Linux when they provided additional
  features on top of the regular NSS that is not shipped by the vanilla library

Starting in 7.82.0, building curl to use NSS configure requires the additional
flag `--with-nss-deprecated` in an attempt to highlight these plans.

## gskit

We remove support for building curl with the gskit TLS library in August 2023.

- This is a niche TLS library, only running on some IBM systems
- no regular curl contributors use this backend
- no CI builds use or verify this backend
- gskit, or the curl adaption for it, lacks many modern TLS features making it
  an inferior solution
- build breakages in this code take weeks or more to get detected
- fixing gskit code is mostly done "flying blind"

## mingw v1

We remove support for building curl with the original legacy mingw version 1
in September 2023.

During the deprecation period you can enable the support with the configure
option `--with-mingw1-deprecated`.

mingw version 1 is old and deprecated software. There are much better and
still support build environments to use to build curl and other software. For
example [MinGW-w64](https://www.mingw-w64.org/).

## space-separated `NOPROXY` patterns

When specifying patterns/domain names for curl that should *not* go through a
proxy, the curl tool features the `--noproxy` command line option and the
library supports the `NO_PROXY` environment variable and the `CURLOPT_NOPROXY`
libcurl option.

They all set the same list of patterns. This list is documented to be a set of
**comma-separated** names, but can also be provided separated with just
space. The ability to just use spaces for this has never been documented but
some users may still have come to rely on this.

Several other tools and utilities also parse the `NO_PROXY` environment
variable but do not consider a space to be a valid separator. Using spaces for
separator is probably less portable and might cause more friction than commas
do. Users should use commas for this for greater portability.

curl will remove the support for space-separated names in July 2024.

## past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
 - Support for systems without 64 bit data types
