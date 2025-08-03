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

AC_DEFUN([CURL_DARWIN_SYSTEMCONFIGURATION], [
AC_MSG_CHECKING([whether to link macOS CoreFoundation, CoreServices, and SystemConfiguration frameworks])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <TargetConditionals.h>
    ]],[[
      #if TARGET_OS_MAC && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
        return 0;
      #else
        #error Not macOS
      #endif
    ]])
  ],[
    build_for_macos="yes"
  ],[
    build_for_macos="no"
  ])
  if test "x$build_for_macos" != xno; then
    AC_MSG_RESULT(yes)
    SYSCONFIG_LDFLAGS='-framework CoreFoundation -framework CoreServices -framework SystemConfiguration'
    LDFLAGS="$LDFLAGS $SYSCONFIG_LDFLAGS"
    LDFLAGSPC="$LDFLAGSPC $SYSCONFIG_LDFLAGS"
  else
    AC_MSG_RESULT(no)
  fi
])
