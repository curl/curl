# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

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
 - NSS
 - gskit
 - mingw v1
