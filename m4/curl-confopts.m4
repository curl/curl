#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# $Id$
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 4


dnl CURL_CHECK_OPTION_DEBUG
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-debug or --disable-debug, and set shell
dnl variable want_debug value as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_DEBUG], [
  AC_BEFORE([$0],[CURL_CHECK_OPTION_WARNINGS])dnl
  AC_BEFORE([$0],[CURL_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable debug build options])
  OPT_DEBUG_BUILD="default"
  AC_ARG_ENABLE(debug,
AC_HELP_STRING([--enable-debug],[Enable debug build options])
AC_HELP_STRING([--disable-debug],[Disable debug build options]),
  OPT_DEBUG_BUILD=$enableval)
  case "$OPT_DEBUG_BUILD" in
    no)
      dnl --disable-debug option used
      want_debug="no"
      ;;
    default)
      dnl configure option not specified
      want_debug="no"
      ;;
    *)
      dnl --enable-debug option used
      want_debug="yes"
      ;;
  esac
  AC_MSG_RESULT([$want_debug])
])


dnl CURL_CHECK_OPTION_NONBLOCKING
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-nonblocking or --disable-nonblocking, and
dnl set shell variable want_nonblocking as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_NONBLOCKING], [
  AC_BEFORE([$0],[CURL_CHECK_NONBLOCKING_SOCKET])dnl
  AC_MSG_CHECKING([whether to enable non-blocking communications])
  OPT_NONBLOCKING="default"
  AC_ARG_ENABLE(nonblocking,
AC_HELP_STRING([--enable-nonblocking],[Enable non-blocking communications])
AC_HELP_STRING([--disable-nonblocking],[Disable non-blocking communications]),
  OPT_NONBLOCKING=$enableval)
  case "$OPT_NONBLOCKING" in
    no)
      dnl --disable-nonblocking option used
      want_nonblocking="no"
      ;;
    default)
      dnl configure option not specified
      want_nonblocking="yes"
      ;;
    *)
      dnl --enable-nonblocking option used
      want_nonblocking="yes"
      ;;
  esac
  AC_MSG_RESULT([$want_nonblocking])
])


dnl CURL_CHECK_OPTION_OPTIMIZE
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-optimize or --disable-optimize, and set
dnl shell variable want_optimize value as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_OPTIMIZE], [
  AC_REQUIRE([CURL_CHECK_OPTION_DEBUG])dnl
  AC_BEFORE([$0],[CURL_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable compiler optimizer])
  OPT_COMPILER_OPTIMIZE="default"
  AC_ARG_ENABLE(optimize,
AC_HELP_STRING([--enable-optimize],[Enable compiler optimizations])
AC_HELP_STRING([--disable-optimize],[Disable compiler optimizations]),
  OPT_COMPILER_OPTIMIZE=$enableval)
  case "$OPT_COMPILER_OPTIMIZE" in
    no)
      dnl --disable-optimize option used. We will handle this as
      dnl a request to disable compiler optimizations if possible.
      dnl If the compiler is known CFLAGS and CPPFLAGS will be
      dnl overridden, otherwise this can not be honored.
      want_optimize="no"
      AC_MSG_RESULT([no])
      ;;
    default)
      dnl configure's optimize option not specified. Initially we will
      dnl handle this as a a request contrary to configure's setting
      dnl for --enable-debug. IOW, initially, for debug-enabled builds
      dnl this will be handled as a request to disable optimizations if
      dnl possible, and for debug-disabled builds this will be handled
      dnl initially as a request to enable optimizations if possible.
      dnl Finally, if the compiler is known and CFLAGS and CPPFLAGS do
      dnl not have any optimizer flag the request will be honored, in
      dnl any other case the request can not be honored.
      dnl IOW, existing optimizer flags defined in CFLAGS or CPPFLAGS
      dnl will always take precedence over any initial assumption.
      if test "$want_debug" = "yes"; then
        want_optimize="assume_no"
        AC_MSG_RESULT([not specified (assuming no)])
      else
        want_optimize="assume_yes"
        AC_MSG_RESULT([not specified (assuming yes)])
      fi
      ;;
    *)
      dnl --enable-optimize option used. We will handle this as
      dnl a request to enable compiler optimizations if possible.
      dnl If the compiler is known CFLAGS and CPPFLAGS will be
      dnl overridden, otherwise this can not be honored.
      want_optimize="yes"
      AC_MSG_RESULT([yes])
      ;;
  esac
])


dnl CURL_CHECK_OPTION_WARNINGS
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-warnings or --disable-warnings, and set
dnl shell variable want_warnings as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_WARNINGS], [
  AC_REQUIRE([CURL_CHECK_OPTION_DEBUG])dnl
  AC_BEFORE([$0],[CURL_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable strict compiler warnings])
  OPT_COMPILER_WARNINGS="default"
  AC_ARG_ENABLE(warnings,
AC_HELP_STRING([--enable-warnings],[Enable strict compiler warnings])
AC_HELP_STRING([--disable-warnings],[Disable strict compiler warnings]),
  OPT_COMPILER_WARNINGS=$enableval)
  case "$OPT_COMPILER_WARNINGS" in
    no)
      dnl --disable-warnings option used
      want_warnings="no"
      ;;
    default)
      dnl configure option not specified, so
      dnl use same setting as --enable-debug
      want_warnings="$want_debug"
      ;;
    *)
      dnl --enable-warnings option used
      want_warnings="yes"
      ;;
  esac
  AC_MSG_RESULT([$want_warnings])
])


dnl CURL_CHECK_NONBLOCKING_SOCKET
dnl -------------------------------------------------
dnl Check for how to set a socket into non-blocking state.

AC_DEFUN([CURL_CHECK_NONBLOCKING_SOCKET], [
  AC_REQUIRE([CURL_CHECK_OPTION_NONBLOCKING])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_FCNTL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTLSOCKET])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_SETSOCKOPT])dnl
  #
  tst_method="unknown"
  if test "$want_nonblocking" = "yes"; then
    AC_MSG_CHECKING([how to set a socket into non-blocking mode])
    if test "x$ac_cv_func_fcntl_o_nonblock" = "xyes"; then
      tst_method="fcntl O_NONBLOCK"
    elif test "x$ac_cv_func_ioctl_fionbio" = "xyes"; then
      tst_method="ioctl FIONBIO"
    elif test "x$ac_cv_func_ioctlsocket_fionbio" = "xyes"; then
      tst_method="ioctlsocket FIONBIO"
    elif test "x$ac_cv_func_ioctlsocket_camel_fionbio" = "xyes"; then
      tst_method="IoctlSocket FIONBIO"
    elif test "x$ac_cv_func_setsockopt_so_nonblock" = "xyes"; then
      tst_method="setsockopt SO_NONBLOCK"
    fi
    AC_MSG_RESULT([$tst_method])
    if test "$tst_method" = "unknown"; then
      AC_MSG_WARN([cannot determine non-blocking socket method.])
    fi
  fi
  if test "$tst_method" = "unknown"; then
    AC_DEFINE_UNQUOTED(USE_BLOCKING_SOCKETS, 1,
      [Define to disable non-blocking sockets.])
    AC_MSG_WARN([non-blocking sockets disabled.])
  fi
])

