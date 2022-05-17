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

AC_DEFUN([CURL_DARWIN_SYSTEMCONFIGURATION], [
AC_MSG_CHECKING([whether to link macOS CoreFoundation and SystemConfiguration framework])
case $host_os in
  darwin*)
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <TargetConditionals.h>
      ]],[[
#if (TARGET_OS_OSX)
      return 0;
#else
#error Not a macOS
#endif
      ]])
    ],[
      build_for_macos="yes"
    ],[
      build_for_macos="no"
    ])
    if test "x$build_for_macos" != xno; then
      AC_MSG_RESULT(yes)
      LDFLAGS="$LDFLAGS -framework CoreFoundation -framework SystemConfiguration"
    else
      AC_MSG_RESULT(no)
    fi
    ;;
  *)
    AC_MSG_RESULT(no)
esac
])
