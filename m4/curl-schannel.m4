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

AC_DEFUN([CURL_WITH_SCHANNEL], [
AC_MSG_CHECKING([whether to enable Windows native SSL/TLS])
if test "x$OPT_SCHANNEL" != xno; then
  ssl_msg=
  if test "x$OPT_SCHANNEL" != "xno"  &&
     test "x$curl_cv_native_windows" = "xyes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_SCHANNEL, 1, [to enable Windows native SSL/TLS support])
    AC_SUBST(USE_SCHANNEL, [1])
    ssl_msg="Schannel"
    test schannel != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
    SCHANNEL_ENABLED=1
    # --with-schannel implies --enable-sspi
    AC_DEFINE(USE_WINDOWS_SSPI, 1, [to enable SSPI support])
    AC_SUBST(USE_WINDOWS_SSPI, [1])
    curl_sspi_msg="enabled"
  else
    AC_MSG_RESULT(no)
  fi
  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
else
  AC_MSG_RESULT(no)
fi
])
