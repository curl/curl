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

## c-ares 1.16.0

In March 2026, we drop support for all c-ares versions before 1.16.0.

## RTMP

RTMP in curl is powered by the 3rd party library librtmp.

- RTMP is barely used by curl users (2.2% in the 2025 survey)
- librtmp has no test cases, makes no proper releases and has not had a single
  commit within the last year
- librtmp parses the URL itself and requires non-compliant URLs for this
- we have no RTMP tests

Support for RTMP in libcurl gets removed in April 2026.

## CMake 3.17 and earlier

We remove support for CMake <3.18 in April 2026.

CMake 3.18 was released on 2020-07-15.

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
- winbuild build system (removed in 8.17.0)
- Windows CE (removed in 8.18.0)
- Support for Visual Studio 2008 (removed in 8.18.0)
- OpenSSL 1.1.1 and older (removed in 8.18.0)
- Support for Windows XP (removed in 8.19.0)
- OpenSSL-QUIC (removed in 8.19.0)
