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

## msh3 support

The msh3 backed for QUIC and HTTP/3 was introduced in April 2022 but has never
been made to work properly. It has seen no visible traction or developer
activity from the msh3 main author (or anyone else seemingly interested) in
two years. As a non-functional backend, it only adds friction and "weight" to
the development and maintenance.

Meanwhile, we have a fully working backend in the ngtcp2 one and we have two
fully working backends in OpenSSL-QUIC and quiche well on their way of ending
their experimental status in a future.

We remove msh3 support from the curl source tree in July 2025.

## winbuild build system

curl drops support for the winbuild build method after September 2025.

We recommend migrating to CMake. See the migration guide in
`docs/INSTALL-CMAKE.md`.

## Past removals

 - Pipelining
 - axTLS
 - PolarSSL
 - NPN
 - Support for systems without 64-bit data types
 - NSS
 - gskit
 - MinGW v1
 - NTLM_WB
 - space-separated `NOPROXY` patterns
 - hyper
