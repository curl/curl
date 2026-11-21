#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************
AC_PREREQ([2.69])
AC_INIT([schannel-mockup], [0.1.0], [curl-library@cool.haxx.se])
AC_CONFIG_SRCDIR([src/mock_sspi.c])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_AR
LT_INIT

# Check for OpenSSL
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.1], [
  HAVE_OPENSSL=yes
], [
  HAVE_OPENSSL=no
  AC_CHECK_HEADER([openssl/ssl.h], [
    AC_CHECK_LIB([crypto], [X509_new], [
      AC_CHECK_LIB([ssl], [SSL_CTX_new], [
        HAVE_OPENSSL=yes
        OPENSSL_LIBS="-lssl -lcrypto"
        OPENSSL_CFLAGS=""
      ])
    ])
  ])
])

if test "x$HAVE_OPENSSL" != "xyes"; then
  AC_MSG_ERROR([OpenSSL development libraries (libssl, libcrypto) are required])
fi

AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])

# Check for perl (used by checksrc if available)
AC_PATH_PROG([PERL], [perl])

AC_ARG_ENABLE([werror],
  [AS_HELP_STRING([--enable-werror], [Treat warnings as errors])],
  [enable_werror=$enableval], [enable_werror=no])

WARN_CFLAGS="-Wall -Wextra -pedantic"
if test "x$enable_werror" = "xyes"; then
  WARN_CFLAGS="$WARN_CFLAGS -Werror"
fi
AC_SUBST([WARN_CFLAGS])

AC_CONFIG_FILES([
  Makefile
  tests/Makefile
  schannel-mockup.pc
])

AC_OUTPUT
