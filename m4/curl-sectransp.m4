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

AC_DEFUN([CURL_WITH_SECURETRANSPORT], [
AC_MSG_CHECKING([whether to enable Secure Transport])
if test "x$OPT_SECURETRANSPORT" != xno; then
  if test "x$OPT_SECURETRANSPORT" != "xno" &&
     (test "x$cross_compiling" != "xno" || test -d "/System/Library/Frameworks/Security.framework"); then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_SECTRANSP, 1, [enable Secure Transport])
    AC_SUBST(USE_SECTRANSP, [1])
    ssl_msg="Secure Transport"
    test secure-transport != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
    SECURETRANSPORT_ENABLED=1
    SECURETRANSPORT_LDFLAGS='-framework CoreFoundation -framework CoreServices -framework Security'
    LDFLAGS="$LDFLAGS $SECURETRANSPORT_LDFLAGS"
    LDFLAGSPC="$LDFLAGSPC $SECURETRANSPORT_LDFLAGS"
  else
    AC_MSG_RESULT(no)
  fi
  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
else
  AC_MSG_RESULT(no)
fi

])
