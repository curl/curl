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

## TLS-SRP Authentication

Transport Layer Security Secure Remote Password is a TLS feature that does not
work with TLS 1.3 or QUIC and is virtually unused by curl users and in
general.

TLS-SRP support gets removed in August 2026.

## SMB goes opt-in

The SMB protocol has weak security and is rarely used these days.

SMB support gets removed in September 2026.

## NTLM goes opt-in

The NTLM authentication method has weak security and is rarely used these
days. It has been deprecated by Microsoft and does not work over HTTP/2 or
HTTP/3.

NTLM support gets removed in September 2026

## Local crypto implementations

Since the dawn of time, curl bundles code for a few crypto and hash algorithms
in order to enable functionality for builds without TLS libraries. This list
includes MD4, MD5, SHA256, SHA256_512 and perhaps something more.

Meanwhile, curl is almost always built to use a TLS/crypto library which for
sure has better maintained and better performing versions of these algorithms.

Also, the local curl implementations are not as widely tested since curl
builds without TLS are rare.

Since these implementations are going away, a good idea is to verify ahead of
time that builds using your preferred TLS library use the crypto functions
provided by that library and are not bundled by curl.

The removal of local crypto functions subsequently disables some functions in
future curl versions when built without TLS support. For example Digest.

Local crypto gets removed in October 2026.

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
- CMake 3.17 and older (removed in 8.20.0)
- RTMP (removed in 8.20.0)
- SMB (became opt-in in 8.20.0)
- NTLM (became opt-in in 8.20.0)
- c-ares < 1.16.0 (removed in 8.20.0)
