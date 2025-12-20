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

AC_DEFUN([CURL_WITH_APPLE_SECTRUST], [
AC_MSG_CHECKING([whether to enable Apple OS native certificate validation])
if test "x$OPT_APPLE_SECTRUST" = "xyes"; then
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <TargetConditionals.h>
    ]],[[
      #if TARGET_OS_MAC
        return 0;
      #else
      #error Not macOS
      #endif
    ]])
  ],[
    build_for_apple="yes"
  ],[
    build_for_apple="no"
  ])
  if test "$build_for_apple" = "no"; then
    AC_MSG_ERROR([Apple SecTrust can only be enabled for Apple OS targets])
  fi
  if test "$OPENSSL_ENABLED" = "1" || test "$GNUTLS_ENABLED" = "1"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_APPLE_SECTRUST, 1, [enable Apple OS certificate validation])
    APPLE_SECTRUST_ENABLED=1
    APPLE_SECTRUST_LDFLAGS='-framework CoreFoundation -framework CoreServices -framework Security'
    LDFLAGS="$LDFLAGS $APPLE_SECTRUST_LDFLAGS"
    LDFLAGSPC="$LDFLAGSPC $APPLE_SECTRUST_LDFLAGS"
  else
    AC_MSG_ERROR([Apple SecTrust is only supported for OpenSSL/GnuTLS builds])
  fi
else
  AC_MSG_RESULT(no)
fi

])
