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

 - OpenSSL      3.0.0 (2021-09-07)
 - LibreSSL     2.9.1 (2019-04-22)
 - GnuTLS       3.6.5 (2018-12-01)
 - mbedTLS      3.2.0 (2022-07-11)
 - zlib         1.2.5.2 (2011-12-11)
 - libssh2      1.9.0 (2019-06-20)
 - c-ares       1.6.0 (2008-12-09)
 - libssh       0.9.0 (2019-06-28)
 - libidn2      2.0.0 (2017-03-29)
 - wolfSSL      3.4.6 (2017-09-22)
 - OpenLDAP     2.0 (2000-08-01)
 - MIT Kerberos 1.3 (2003-07-31)
 - nghttp2      1.15.0 (2016-09-25)

## Build tools

 When writing code (mostly for generating stuff included in release tarballs)
 we use a few "build tools" and we make sure that we remain functional with
 these versions:

 - GNU Libtool  1.4.2
 - GNU Autoconf 2.59
 - GNU Automake 1.7
 - GNU M4       1.4
 - perl         5.8 (5.22 on Windows)
 - roffit       0.5
 - cmake        3.7

Library Symbols
===============

 All symbols used internally in libcurl must use a `Curl_` prefix if they are
 used in more than a single file. Single-file symbols must be made static.
 Public ("exported") symbols must use a `curl_` prefix. Public API functions
 are marked with `CURL_EXTERN` in the public header files so that all others
 can be hidden on platforms where this is possible.
