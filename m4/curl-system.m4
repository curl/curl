#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 3


dnl CURL_CHECK_PATH_SEPARATOR
dnl -------------------------------------------------
dnl Check and compute the path separator for us. This
dnl path separator is the symbol used to diferentiate
dnl or separate paths inside the PATH environment var.

AC_DEFUN([CURL_CHECK_PATH_SEPARATOR], [
  if test -z "$curl_cv_PATH_SEPARATOR"; then
    if test -z "$PATH"; then
      AC_MSG_ERROR([PATH not set. Cannot continue without PATH being set.])
    fi
    dnl Directory count in PATH when using a colon separator.
    tst_dirs_col=0
    tst_save_IFS=$IFS; IFS=':'
    for tst_dir in $PATH; do
      IFS=$tst_save_IFS
      test -d "$tst_dir" && tst_dirs_col=`expr $tst_dirs_col + 1`
    done
    IFS=$tst_save_IFS
    dnl Directory count in PATH when using a semicolon separator.
    tst_dirs_sem=0
    tst_save_IFS=$IFS; IFS=';'
    for tst_dir in $PATH; do
      IFS=$tst_save_IFS
      test -d "$tst_dir" && tst_dirs_sem=`expr $tst_dirs_sem + 1`
    done
    IFS=$tst_save_IFS
    if test $tst_dirs_sem -eq $tst_dirs_col; then
      dnl When both counting methods give the same result we do not want to
      dnl chose one over the other, and consider auto-detection not possible.
      if test -z "$PATH_SEPARATOR"; then
        dnl Stop dead until user provides PATH_SEPARATOR definition.
        AC_MSG_ERROR([PATH_SEPARATOR not set. Cannot continue without it.])
      fi
    else
      dnl Separator with the greater directory count is the auto-detected one.
      if test $tst_dirs_sem -gt $tst_dirs_col; then
        tst_auto_separator=';'
      else
        tst_auto_separator=':'
      fi
      if test -z "$PATH_SEPARATOR"; then
        dnl Simply use the auto-detected one when not already set.
        PATH_SEPARATOR="$tst_auto_separator"
      fi
    fi
    curl_cv_PATH_SEPARATOR="$PATH_SEPARATOR"
  fi
  AC_SUBST([PATH_SEPARATOR])
  AC_SUBST([PATH])
])


dnl CURL_CHECK_PATH_SEPARATOR_REQUIRED
dnl -------------------------------------------------
dnl Use this to ensure that the path separator check
dnl macro is only expanded and included once.

AC_DEFUN([CURL_CHECK_PATH_SEPARATOR_REQUIRED], [
  AC_REQUIRE([CURL_CHECK_PATH_SEPARATOR])dnl
])

