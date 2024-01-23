# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## NTLM_WB auth

This NTLM authentication method is powered by a separate tool,
`ntlm_auth`. Barely anyone uses this method. It was always a quirky
implementation (including fork + exec), it has limited portability and we do
not test it in the test suite and CI.

We keep the native NTLM implementation.

Due to a mistake, the `NTLM_WB` functionality is missing in builds since 8.4.0
(October 2023). It needs to be manually patched to work. See [PR
12479](https://github.com/curl/curl/pull/12479).

curl will remove the support for NTLM_WB auth in April 2024.

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
