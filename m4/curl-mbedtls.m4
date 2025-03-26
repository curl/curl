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

dnl ----------------------------------------------------
dnl check for mbedTLS
dnl ----------------------------------------------------
AC_DEFUN([CURL_WITH_MBEDTLS], [

if test "x$OPT_MBEDTLS" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  _ldflagspc=$LDFLAGSPC
  ssl_msg=

  if test X"$OPT_MBEDTLS" != Xno; then

    if test "$OPT_MBEDTLS" = "yes"; then
      OPT_MBEDTLS=""
    fi

    if test -z "$OPT_MBEDTLS" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(mbedtls, mbedtls_havege_init,
      dnl libmbedtls found, set the variable
      [
        AC_DEFINE(USE_MBEDTLS, 1, [if mbedTLS is enabled])
        MBEDTLS_ENABLED=1
        USE_MBEDTLS="yes"
        ssl_msg="mbedTLS"
        test mbedtls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
      ], [], -lmbedx509 -lmbedcrypto)
    fi

    addld=""
    addlib=""
    addcflags=""
    mbedtlslib=""

    if test "x$USE_MBEDTLS" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_MBEDTLS/lib$libsuff
      addcflags=-I$OPT_MBEDTLS/include
      mbedtlslib=$OPT_MBEDTLS/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      LDFLAGSPC="$LDFLAGSPC $addld"
      if test "$addcflags" != "-I/usr/include"; then
        CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(mbedtls, mbedtls_ssl_init,
        [
        AC_DEFINE(USE_MBEDTLS, 1, [if mbedTLS is enabled])
        MBEDTLS_ENABLED=1
        USE_MBEDTLS="yes"
        ssl_msg="mbedTLS"
        test mbedtls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ],
        [
          CPPFLAGS=$_cppflags
          LDFLAGS=$_ldflags
          LDFLAGSPC=$_ldflagspc
        ], -lmbedx509 -lmbedcrypto)
    fi

    if test "x$USE_MBEDTLS" = "xyes"; then
      AC_MSG_NOTICE([detected mbedTLS])
      check_for_ca_bundle=1

      LIBS="-lmbedtls -lmbedx509 -lmbedcrypto $LIBS"

      if test -n "$mbedtlslib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$mbedtlslib"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $mbedtlslib to CURL_LIBRARY_PATH])
        fi
      fi
      dnl FIXME: Enable when mbedTLS was detected via pkg-config
      if false; then
        LIBCURL_PC_REQUIRES_PRIVATE="$LIBCURL_PC_REQUIRES_PRIVATE mbedtls mbedx509 mbedcrypto"
      fi
    fi

  fi dnl mbedTLS not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi

])
