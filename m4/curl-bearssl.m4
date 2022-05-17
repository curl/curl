#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

AC_DEFUN([CURL_WITH_BEARSSL], [
dnl ----------------------------------------------------
dnl check for BearSSL
dnl ----------------------------------------------------

if test "x$OPT_BEARSSL" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  ssl_msg=

  if test X"$OPT_BEARSSL" != Xno; then

    if test "$OPT_BEARSSL" = "yes"; then
      OPT_BEARSSL=""
    fi

    if test -z "$OPT_BEARSSL" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(bearssl, br_ssl_client_init_full,
      dnl libbearssl found, set the variable
       [
         AC_DEFINE(USE_BEARSSL, 1, [if BearSSL is enabled])
         AC_SUBST(USE_BEARSSL, [1])
         BEARSSL_ENABLED=1
         USE_BEARSSL="yes"
         ssl_msg="BearSSL"
	 test bearssl != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ], [], -lbearssl)
    fi

    addld=""
    addlib=""
    addcflags=""
    bearssllib=""

    if test "x$USE_BEARSSL" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_BEARSSL/lib$libsuff
      addcflags=-I$OPT_BEARSSL/include
      bearssllib=$OPT_BEARSSL/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(bearssl, br_ssl_client_init_full,
       [
       AC_DEFINE(USE_BEARSSL, 1, [if BearSSL is enabled])
       AC_SUBST(USE_BEARSSL, [1])
       BEARSSL_ENABLED=1
       USE_BEARSSL="yes"
       ssl_msg="BearSSL"
       test bearssl != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       [
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
       ], -lbearssl)
    fi

    if test "x$USE_BEARSSL" = "xyes"; then
      AC_MSG_NOTICE([detected BearSSL])
      check_for_ca_bundle=1

      LIBS="-lbearssl $LIBS"

      if test -n "$bearssllib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$bearssllib"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $bearssllib to CURL_LIBRARY_PATH])
        fi
      fi
    fi

  fi dnl BearSSL not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi
])
