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

## Windows CE

Windows CE "mainstream support" ended on October 9, 2018, and "Extended
Support" ended on October 10, 2023.

curl drops all support in November 2025.

## VS2008

curl drops support for getting built with Microsoft Visual Studio 2008 in
November 2025.

The only reason we kept support for this version is for Windows CE - and we
intend to remove support for that Operating System in this time frame as well.
Bumping the minimum to VS2010. VS2008 is a pain to support.

Previous discussion and details: https://github.com/curl/curl/discussions/15972

## Past removals

 - axTLS (removed in 7.63.0)
 - Pipelining (removed in 7.65.0)
 - PolarSSL (removed in 7.69.0)
 - NPN (removed in 7.86.0)
 - Support for systems without 64-bit data types (removed in 8.0.0)
 - NSS (removed in 8.3.0)
 - gskit (removed in 8.3.0)
 - MinGW v1 (removed in 8.4.0)
 - NTLM_WB (removed in 8.8.0)
 - space-separated `NOPROXY` patterns (removed in 8.9.0)
 - hyper (removed in 8.12.0)
