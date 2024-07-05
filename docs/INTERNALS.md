<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl internals

The canonical libcurl internals documentation is now in the [everything
curl](https://everything.curl.dev/internals) book. This file lists supported
versions of libs and build tools.

## Portability

 We write curl and libcurl to compile with C89 compilers on 32-bit and up
 machines. Most of libcurl assumes more or less POSIX compliance but that is
 not a requirement.

 We write libcurl to build and work with lots of third party tools, and we
 want it to remain functional and buildable with these and later versions
 (older versions may still work but is not what we work hard to maintain):

## Dependencies

 We aim to support these or later versions.

 - OpenSSL      0.9.7
 - GnuTLS       3.1.10
 - zlib         1.1.4
 - libssh2      1.0
 - c-ares       1.16.0
 - libidn2      2.0.0
 - wolfSSL      2.0.0
 - OpenLDAP     2.0
 - MIT Kerberos 1.2.4
 - Heimdal      ?
 - nghttp2      1.15.0
 - WinSock      2.2 (on Windows 95+ and Windows CE .NET 4.1+)

## Build tools

 When writing code (mostly for generating stuff included in release tarballs)
 we use a few "build tools" and we make sure that we remain functional with
 these versions:

 - GNU Libtool  1.4.2
 - GNU Autoconf 2.59
 - GNU Automake 1.7
 - GNU M4       1.4
 - perl         5.8
 - roffit       0.5
 - cmake        3.7

Library Symbols
===============

 All symbols used internally in libcurl must use a `Curl_` prefix if they are
 used in more than a single file. Single-file symbols must be made static.
 Public ("exported") symbols must use a `curl_` prefix. Public API functions
 are marked with `CURL_EXTERN` in the public header files so that all others
 can be hidden on platforms where this is possible.
