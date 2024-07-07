<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Items to be removed from future curl releases

If any of these deprecated features is a cause for concern for you, please
email the
[curl-library mailing list](https://lists.haxx.se/listinfo/curl-library)
as soon as possible and explain to us why this is a problem for you and
how your use case cannot be satisfied properly using a workaround.

## TLS libraries without 1.3 support

curl drops support for TLS libraries without TLS 1.3 capability after May
2025.

It requires that a curl build using the library should be able to negotiate
and use TLS 1.3, or else it is not good enough.

As of May 2024, the libraries that need to get fixed to remain supported after
May 2025 are: BearSSL and Secure Transport.

## Past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
 - Support for systems without 64-bit data types
 - NSS
 - gskit
 - mingw v1
 - NTLM_WB
 - space-separated `NOPROXY` patterns
