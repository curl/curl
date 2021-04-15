#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#***************************************************************************

AC_DEFUN([CURL_WITH_AMISSL], [
AC_MSG_CHECKING([whether to enable Amiga native SSL/TLS (AmiSSL)])
if test "$HAVE_PROTO_BSDSOCKET_H" = "1"; then
  if test "x$OPT_AMISSL" != xno; then
    ssl_msg=
    if test "x$OPT_AMISSL" != "xno"; then
      AC_MSG_RESULT(yes)
      ssl_msg="AmiSSL"
      test amissl != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
      AMISSL_ENABLED=1
      LIBS="-lamisslauto $LIBS"
      AC_DEFINE(USE_AMISSL, 1, [if AmiSSL is in use])
      AC_DEFINE(USE_OPENSSL, 1, [if OpenSSL is in use])
    else
      AC_MSG_RESULT(no)
    fi
    test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

])
