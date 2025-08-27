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

## Windows XP

In January 2026, curl drops support for Windows XP and Server 2003. Their
"mainstream support" ended in 2014, with final updates on May 14, 2019.

Making the new minimum target Windows version Vista / Server 2008.

## c-ares 1.16.0

In March 2026, we drop support for all c-ares versions before 1.16.0.

## OpenSSL 1.0.2

OpenSSL and others only ship fixes for this version to paying customers,
meaning users of the free version risk being vulnerable.

We remove support for this OpenSSL version from curl in December 2025.

## OpenSSL 1.1.1

OpenSSL and others only ship fixes to paying customers, meaning users of the
free version risk being vulnerable.

We remove support for this OpenSSL version from curl in June 2026.

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
 - Support for Visual Studio 2005 and older (removed in 8.13.0)
 - Secure Transport (removed in 8.15.0)
 - BearSSL (removed in 8.15.0)
 - msh3 (removed in 8.16.0)
