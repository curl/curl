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

AC_DEFUN([CURL_WITH_RUSTLS], [
dnl ----------------------------------------------------
dnl check for rustls
dnl ----------------------------------------------------

if test "x$OPT_RUSTLS" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  ssl_msg=

  if test X"$OPT_RUSTLS" != Xno; then

    if test "$OPT_RUSTLS" = "yes"; then
      OPT_RUSTLS=""
    fi

    if test -z "$OPT_RUSTLS" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(rustls, rustls_client_session_read,
      dnl librustls found, set the variable
       [
         AC_DEFINE(USE_RUSTLS, 1, [if rustls is enabled])
         AC_SUBST(USE_RUSTLS, [1])
         RUSTLS_ENABLED=1
         USE_RUSTLS="yes"
         ssl_msg="rustls"
	 test rustls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ], [], -lpthread -ldl -lm)
    fi

    if test "x$USE_RUSTLS" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_RUSTLS/lib$libsuff
      addcflags=-I$OPT_RUSTLS/include
      rustlslib=$OPT_RUSTLS/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(rustls, rustls_connection_read,
       [
       AC_DEFINE(USE_RUSTLS, 1, [if rustls is enabled])
       AC_SUBST(USE_RUSTLS, [1])
       RUSTLS_ENABLED=1
       USE_RUSTLS="yes"
       ssl_msg="rustls"
       test rustls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       AC_MSG_ERROR([--with-rustls was specified but could not find rustls.]),
       -lpthread -ldl -lm)
    fi

    if test "x$USE_RUSTLS" = "xyes"; then
      AC_MSG_NOTICE([detected rustls])
      check_for_ca_bundle=1

      LIBS="-lrustls -lpthread -ldl -lm $LIBS"

      if test -n "$rustlslib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$rustlslib"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $rustlslib to CURL_LIBRARY_PATH])
        fi
      fi
    fi

  fi dnl rustls not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi
])
