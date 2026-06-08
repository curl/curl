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
not a requirement. The compiler must support a 64-bit integer type as well as
supply a stdint.h header file that defines C99-style fixed-width integer types
like uint32_t.

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
 - Winsock      2.2 (on Windows 95+ and Windows CE .NET 4.1+)
>>>>>>> parent of 76f83f0db2 (content_encoding: drop support for zlib before 1.2.0.4)

## Build tools

When writing code (mostly for generating stuff included in release tarballs)
we use a few "build tools" and we make sure that we remain functional with
these versions:

- clang-tidy     17.0.0 (2023-09-19), recommended: 19.1.0 or later (2024-09-17)
- cmake          3.18 (2020-07-15)
- GNU autoconf   2.59 (2003-11-06)
- GNU automake   1.7 (2002-09-25)
- GNU libtool    1.4.2 (2001-09-11)
- GNU m4         1.4 (2007-09-21)
- mingw-w64      3.0 (2013-09-20)
- perl           5.8 (2002-07-19), on Windows: 5.22 (2015-06-01)
- Visual Studio  2010 10.0 (2010-04-12 - 2020-07-14)

## Library Symbols

All symbols used internally in libcurl must use a `Curl_` prefix if they are
used in more than a single file. Single-file symbols must be made static.
Public ("exported") symbols must use a `curl_` prefix. Public API functions
are marked with `CURL_EXTERN` in the public header files so that all others
can be hidden on platforms where this is possible.
