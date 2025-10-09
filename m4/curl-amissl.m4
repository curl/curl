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

AC_DEFUN([CURL_WITH_AMISSL], [
AC_MSG_CHECKING([whether to enable Amiga native SSL/TLS (AmiSSL v5)])
if test "$HAVE_PROTO_BSDSOCKET_H" = "1"; then
  if test "$OPT_AMISSL" != "no"; then
    ssl_msg=
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #include <libraries/amisslmaster.h>
        #include <openssl/opensslv.h>
      ]],[[
        #if defined(AMISSL_CURRENT_VERSION) && defined(AMISSL_V3xx) && \
            (OPENSSL_VERSION_NUMBER >= 0x30000000L) && \
            defined(PROTO_AMISSL_H)
        return 0;
        #else
        #error not AmiSSL v5 / OpenSSL 3
        #endif
      ]])
    ],[
      AC_MSG_RESULT([yes])
      ssl_msg="AmiSSL"
      test "amissl" != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
      AMISSL_ENABLED=1
      OPENSSL_ENABLED=1
      # Use AmiSSL's built-in ca bundle
      check_for_ca_bundle=1
      with_ca_fallback=yes
      LIBS="-lamisslstubs -lamisslauto $LIBS"
      CURL_NETWORK_AND_TIME_LIBS="-lamisslstubs -lamisslauto $CURL_NETWORK_AND_TIME_LIBS"
      AC_DEFINE(USE_AMISSL, 1, [if AmiSSL is in use])
      AC_DEFINE(USE_OPENSSL, 1, [if OpenSSL is in use])
      AC_CHECK_HEADERS(openssl/x509.h openssl/rsa.h openssl/crypto.h \
                       openssl/pem.h openssl/ssl.h openssl/err.h)
    ],[
      AC_MSG_RESULT([no])
    ])
    test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

])
