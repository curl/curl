#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
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
# serial 73


dnl CURL_INCLUDES_ARPA_INET
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when arpa/inet.h is to be included.

AC_DEFUN([CURL_INCLUDES_ARPA_INET], [
curl_includes_arpa_inet="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/socket.h netinet/in.h arpa/inet.h,
    [], [], [$curl_includes_arpa_inet])
])


dnl CURL_INCLUDES_FCNTL
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when fcntl.h is to be included.

AC_DEFUN([CURL_INCLUDES_FCNTL], [
curl_includes_fcntl="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h unistd.h fcntl.h,
    [], [], [$curl_includes_fcntl])
])


dnl CURL_INCLUDES_IFADDRS
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when ifaddrs.h is to be included.

AC_DEFUN([CURL_INCLUDES_IFADDRS], [
curl_includes_ifaddrs="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_IFADDRS_H
#  include <ifaddrs.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/socket.h netinet/in.h ifaddrs.h,
    [], [], [$curl_includes_ifaddrs])
])


dnl CURL_INCLUDES_INTTYPES
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when inttypes.h is to be included.

AC_DEFUN([CURL_INCLUDES_INTTYPES], [
curl_includes_inttypes="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
/* includes end */"
  case $host_os in
    irix*)
      ac_cv_header_stdint_h="no"
      ;;
  esac
  AC_CHECK_HEADERS(
    sys/types.h stdint.h inttypes.h,
    [], [], [$curl_includes_inttypes])
])


dnl CURL_INCLUDES_LIBGEN
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when libgen.h is to be included.

AC_DEFUN([CURL_INCLUDES_LIBGEN], [
curl_includes_libgen="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_LIBGEN_H
#  include <libgen.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h libgen.h,
    [], [], [$curl_includes_libgen])
])


dnl CURL_INCLUDES_NETDB
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when netdb.h is to be included.

AC_DEFUN([CURL_INCLUDES_NETDB], [
curl_includes_netdb="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h netdb.h,
    [], [], [$curl_includes_netdb])
])


dnl CURL_INCLUDES_POLL
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when poll.h is to be included.

AC_DEFUN([CURL_INCLUDES_POLL], [
curl_includes_poll="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_POLL_H
#  include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h poll.h sys/poll.h,
    [], [], [$curl_includes_poll])
])


dnl CURL_INCLUDES_SETJMP
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when setjmp.h is to be included.

AC_DEFUN([CURL_INCLUDES_SETJMP], [
curl_includes_setjmp="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SETJMP_H
#  include <setjmp.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h setjmp.h,
    [], [], [$curl_includes_setjmp])
])


dnl CURL_INCLUDES_SIGNAL
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when signal.h is to be included.

AC_DEFUN([CURL_INCLUDES_SIGNAL], [
curl_includes_signal="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SIGNAL_H
#  include <signal.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h signal.h,
    [], [], [$curl_includes_signal])
])


dnl CURL_INCLUDES_SOCKET
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when socket.h is to be included.

AC_DEFUN([CURL_INCLUDES_SOCKET], [
curl_includes_socket="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SOCKET_H
#  include <socket.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h socket.h,
    [], [], [$curl_includes_socket])
])


dnl CURL_INCLUDES_STDIO
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when stdio.h is to be included.

AC_DEFUN([CURL_INCLUDES_STDIO], [
curl_includes_stdio="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h stdio.h,
    [], [], [$curl_includes_stdio])
])


dnl CURL_INCLUDES_STDLIB
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when stdlib.h is to be included.

AC_DEFUN([CURL_INCLUDES_STDLIB], [
curl_includes_stdlib="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h stdlib.h,
    [], [], [$curl_includes_stdlib])
])


dnl CURL_INCLUDES_STRING
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when string(s).h is to be included.

AC_DEFUN([CURL_INCLUDES_STRING], [
curl_includes_string="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h string.h strings.h,
    [], [], [$curl_includes_string])
])


dnl CURL_INCLUDES_STROPTS
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when stropts.h is to be included.

AC_DEFUN([CURL_INCLUDES_STROPTS], [
curl_includes_stropts="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h unistd.h sys/socket.h sys/ioctl.h stropts.h,
    [], [], [$curl_includes_stropts])
])


dnl CURL_INCLUDES_SYS_SOCKET
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when sys/socket.h is to be included.

AC_DEFUN([CURL_INCLUDES_SYS_SOCKET], [
curl_includes_sys_socket="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/socket.h,
    [], [], [$curl_includes_sys_socket])
])


dnl CURL_INCLUDES_SYS_TYPES
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when sys/types.h is to be included.

AC_DEFUN([CURL_INCLUDES_SYS_TYPES], [
curl_includes_sys_types="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
    [], [], [$curl_includes_sys_types])
])


dnl CURL_INCLUDES_SYS_UIO
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when sys/uio.h is to be included.

AC_DEFUN([CURL_INCLUDES_SYS_UIO], [
curl_includes_sys_uio="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/uio.h,
    [], [], [$curl_includes_sys_uio])
])


dnl CURL_INCLUDES_SYS_XATTR
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when sys/xattr.h is to be included.

AC_DEFUN([CURL_INCLUDES_SYS_XATTR], [
curl_includes_sys_xattr="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_XATTR_H
#  include <sys/xattr.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/xattr.h,
    [], [], [$curl_includes_sys_xattr])
])

dnl CURL_INCLUDES_TIME
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when time.h is to be included.

AC_DEFUN([CURL_INCLUDES_TIME], [
AC_REQUIRE([AC_HEADER_TIME])dnl
curl_includes_time="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#  ifdef TIME_WITH_SYS_TIME
#    include <time.h>
#  endif
#else
#  ifdef HAVE_TIME_H
#    include <time.h>
#  endif
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h sys/time.h time.h,
    [], [], [$curl_includes_time])
])


dnl CURL_INCLUDES_UNISTD
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when unistd.h is to be included.

AC_DEFUN([CURL_INCLUDES_UNISTD], [
curl_includes_unistd="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h unistd.h,
    [], [], [$curl_includes_unistd])
])


dnl CURL_INCLUDES_WINSOCK2
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when winsock(2).h is to be included.

AC_DEFUN([CURL_INCLUDES_WINSOCK2], [
curl_includes_winsock2="\
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif
/* includes end */"
  CURL_CHECK_HEADER_WINDOWS
  CURL_CHECK_HEADER_WINSOCK
  CURL_CHECK_HEADER_WINSOCK2
])


dnl CURL_INCLUDES_WS2TCPIP
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when ws2tcpip.h is to be included.

AC_DEFUN([CURL_INCLUDES_WS2TCPIP], [
curl_includes_ws2tcpip="\
/* includes start */
#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#    ifdef HAVE_WS2TCPIP_H
#       include <ws2tcpip.h>
#    endif
#  endif
#endif
/* includes end */"
  CURL_CHECK_HEADER_WINDOWS
  CURL_CHECK_HEADER_WINSOCK2
  CURL_CHECK_HEADER_WS2TCPIP
])


dnl CURL_PREPROCESS_CALLCONV
dnl -------------------------------------------------
dnl Set up variable with a preprocessor block which
dnl defines function calling convention.

AC_DEFUN([CURL_PREPROCESS_CALLCONV], [
curl_preprocess_callconv="\
/* preprocess start */
#ifdef HAVE_WINDOWS_H
#  define FUNCALLCONV __stdcall
#else
#  define FUNCALLCONV
#endif
/* preprocess end */"
])


dnl CURL_CHECK_FUNC_ALARM
dnl -------------------------------------------------
dnl Verify if alarm is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_alarm, then
dnl HAVE_ALARM will be defined.

AC_DEFUN([CURL_CHECK_FUNC_ALARM], [
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  #
  tst_links_alarm="unknown"
  tst_proto_alarm="unknown"
  tst_compi_alarm="unknown"
  tst_allow_alarm="unknown"
  #
  AC_MSG_CHECKING([if alarm can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([alarm])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_alarm="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_alarm="no"
  ])
  #
  if test "$tst_links_alarm" = "yes"; then
    AC_MSG_CHECKING([if alarm is prototyped])
    AC_EGREP_CPP([alarm],[
      $curl_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_alarm="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_alarm="no"
    ])
  fi
  #
  if test "$tst_proto_alarm" = "yes"; then
    AC_MSG_CHECKING([if alarm is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_unistd
      ]],[[
        if(0 != alarm(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_alarm="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_alarm="no"
    ])
  fi
  #
  if test "$tst_compi_alarm" = "yes"; then
    AC_MSG_CHECKING([if alarm usage allowed])
    if test "x$curl_disallow_alarm" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_alarm="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_alarm="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if alarm might be used])
  if test "$tst_links_alarm" = "yes" &&
     test "$tst_proto_alarm" = "yes" &&
     test "$tst_compi_alarm" = "yes" &&
     test "$tst_allow_alarm" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_ALARM, 1,
      [Define to 1 if you have the alarm function.])
    curl_cv_func_alarm="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_alarm="no"
  fi
])


dnl CURL_CHECK_FUNC_BASENAME
dnl -------------------------------------------------
dnl Verify if basename is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_basename, then
dnl HAVE_BASENAME will be defined.

AC_DEFUN([CURL_CHECK_FUNC_BASENAME], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  AC_REQUIRE([CURL_INCLUDES_LIBGEN])dnl
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  #
  tst_links_basename="unknown"
  tst_proto_basename="unknown"
  tst_compi_basename="unknown"
  tst_allow_basename="unknown"
  #
  AC_MSG_CHECKING([if basename can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([basename])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_basename="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_basename="no"
  ])
  #
  if test "$tst_links_basename" = "yes"; then
    AC_MSG_CHECKING([if basename is prototyped])
    AC_EGREP_CPP([basename],[
      $curl_includes_string
      $curl_includes_libgen
      $curl_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_basename="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_basename="no"
    ])
  fi
  #
  if test "$tst_proto_basename" = "yes"; then
    AC_MSG_CHECKING([if basename is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
        $curl_includes_libgen
        $curl_includes_unistd
      ]],[[
        if(0 != basename(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_basename="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_basename="no"
    ])
  fi
  #
  if test "$tst_compi_basename" = "yes"; then
    AC_MSG_CHECKING([if basename usage allowed])
    if test "x$curl_disallow_basename" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_basename="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_basename="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if basename might be used])
  if test "$tst_links_basename" = "yes" &&
     test "$tst_proto_basename" = "yes" &&
     test "$tst_compi_basename" = "yes" &&
     test "$tst_allow_basename" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_BASENAME, 1,
      [Define to 1 if you have the basename function.])
    curl_cv_func_basename="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_basename="no"
  fi
])


dnl CURL_CHECK_FUNC_CLOSESOCKET
dnl -------------------------------------------------
dnl Verify if closesocket is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_closesocket, then
dnl HAVE_CLOSESOCKET will be defined.

AC_DEFUN([CURL_CHECK_FUNC_CLOSESOCKET], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_SOCKET])dnl
  #
  tst_links_closesocket="unknown"
  tst_proto_closesocket="unknown"
  tst_compi_closesocket="unknown"
  tst_allow_closesocket="unknown"
  #
  AC_MSG_CHECKING([if closesocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_socket
    ]],[[
      if(0 != closesocket(0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_closesocket="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_closesocket="no"
  ])
  #
  if test "$tst_links_closesocket" = "yes"; then
    AC_MSG_CHECKING([if closesocket is prototyped])
    AC_EGREP_CPP([closesocket],[
      $curl_includes_winsock2
      $curl_includes_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_closesocket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_closesocket="no"
    ])
  fi
  #
  if test "$tst_proto_closesocket" = "yes"; then
    AC_MSG_CHECKING([if closesocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_socket
      ]],[[
        if(0 != closesocket(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_closesocket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_closesocket="no"
    ])
  fi
  #
  if test "$tst_compi_closesocket" = "yes"; then
    AC_MSG_CHECKING([if closesocket usage allowed])
    if test "x$curl_disallow_closesocket" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_closesocket="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_closesocket="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if closesocket might be used])
  if test "$tst_links_closesocket" = "yes" &&
     test "$tst_proto_closesocket" = "yes" &&
     test "$tst_compi_closesocket" = "yes" &&
     test "$tst_allow_closesocket" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_CLOSESOCKET, 1,
      [Define to 1 if you have the closesocket function.])
    curl_cv_func_closesocket="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_closesocket="no"
  fi
])


dnl CURL_CHECK_FUNC_CLOSESOCKET_CAMEL
dnl -------------------------------------------------
dnl Verify if CloseSocket is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_closesocket_camel,
dnl then HAVE_CLOSESOCKET_CAMEL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_CLOSESOCKET_CAMEL], [
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  #
  tst_links_closesocket_camel="unknown"
  tst_proto_closesocket_camel="unknown"
  tst_compi_closesocket_camel="unknown"
  tst_allow_closesocket_camel="unknown"
  #
  AC_MSG_CHECKING([if CloseSocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_sys_socket
    ]],[[
      if(0 != CloseSocket(0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_closesocket_camel="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_closesocket_camel="no"
  ])
  #
  if test "$tst_links_closesocket_camel" = "yes"; then
    AC_MSG_CHECKING([if CloseSocket is prototyped])
    AC_EGREP_CPP([CloseSocket],[
      $curl_includes_sys_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_closesocket_camel="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_closesocket_camel="no"
    ])
  fi
  #
  if test "$tst_proto_closesocket_camel" = "yes"; then
    AC_MSG_CHECKING([if CloseSocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_sys_socket
      ]],[[
        if(0 != CloseSocket(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_closesocket_camel="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_closesocket_camel="no"
    ])
  fi
  #
  if test "$tst_compi_closesocket_camel" = "yes"; then
    AC_MSG_CHECKING([if CloseSocket usage allowed])
    if test "x$curl_disallow_closesocket_camel" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_closesocket_camel="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_closesocket_camel="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if CloseSocket might be used])
  if test "$tst_links_closesocket_camel" = "yes" &&
     test "$tst_proto_closesocket_camel" = "yes" &&
     test "$tst_compi_closesocket_camel" = "yes" &&
     test "$tst_allow_closesocket_camel" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_CLOSESOCKET_CAMEL, 1,
      [Define to 1 if you have the CloseSocket camel case function.])
    curl_cv_func_closesocket_camel="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_closesocket_camel="no"
  fi
])


dnl CURL_CHECK_FUNC_CONNECT
dnl -------------------------------------------------
dnl Verify if connect is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_connect, then
dnl HAVE_CONNECT will be defined.

AC_DEFUN([CURL_CHECK_FUNC_CONNECT], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_INCLUDES_SOCKET])dnl
  #
  tst_links_connect="unknown"
  tst_proto_connect="unknown"
  tst_compi_connect="unknown"
  tst_allow_connect="unknown"
  #
  AC_MSG_CHECKING([if connect can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_sys_socket
      $curl_includes_socket
    ]],[[
      if(0 != connect(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_connect="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_connect="no"
  ])
  #
  if test "$tst_links_connect" = "yes"; then
    AC_MSG_CHECKING([if connect is prototyped])
    AC_EGREP_CPP([connect],[
      $curl_includes_winsock2
      $curl_includes_sys_socket
      $curl_includes_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_connect="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_connect="no"
    ])
  fi
  #
  if test "$tst_proto_connect" = "yes"; then
    AC_MSG_CHECKING([if connect is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_sys_socket
        $curl_includes_socket
      ]],[[
        if(0 != connect(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_connect="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_connect="no"
    ])
  fi
  #
  if test "$tst_compi_connect" = "yes"; then
    AC_MSG_CHECKING([if connect usage allowed])
    if test "x$curl_disallow_connect" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_connect="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_connect="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if connect might be used])
  if test "$tst_links_connect" = "yes" &&
     test "$tst_proto_connect" = "yes" &&
     test "$tst_compi_connect" = "yes" &&
     test "$tst_allow_connect" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_CONNECT, 1,
      [Define to 1 if you have the connect function.])
    curl_cv_func_connect="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_connect="no"
  fi
])


dnl CURL_CHECK_FUNC_FCNTL
dnl -------------------------------------------------
dnl Verify if fcntl is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fcntl, then
dnl HAVE_FCNTL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FCNTL], [
  AC_REQUIRE([CURL_INCLUDES_FCNTL])dnl
  #
  tst_links_fcntl="unknown"
  tst_proto_fcntl="unknown"
  tst_compi_fcntl="unknown"
  tst_allow_fcntl="unknown"
  #
  AC_MSG_CHECKING([if fcntl can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fcntl])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fcntl="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fcntl="no"
  ])
  #
  if test "$tst_links_fcntl" = "yes"; then
    AC_MSG_CHECKING([if fcntl is prototyped])
    AC_EGREP_CPP([fcntl],[
      $curl_includes_fcntl
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fcntl="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fcntl="no"
    ])
  fi
  #
  if test "$tst_proto_fcntl" = "yes"; then
    AC_MSG_CHECKING([if fcntl is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_fcntl
      ]],[[
        if(0 != fcntl(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_fcntl="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_fcntl="no"
    ])
  fi
  #
  if test "$tst_compi_fcntl" = "yes"; then
    AC_MSG_CHECKING([if fcntl usage allowed])
    if test "x$curl_disallow_fcntl" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fcntl="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fcntl="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fcntl might be used])
  if test "$tst_links_fcntl" = "yes" &&
     test "$tst_proto_fcntl" = "yes" &&
     test "$tst_compi_fcntl" = "yes" &&
     test "$tst_allow_fcntl" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FCNTL, 1,
      [Define to 1 if you have the fcntl function.])
    curl_cv_func_fcntl="yes"
    CURL_CHECK_FUNC_FCNTL_O_NONBLOCK
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fcntl="no"
  fi
])


dnl CURL_CHECK_FUNC_FCNTL_O_NONBLOCK
dnl -------------------------------------------------
dnl Verify if fcntl with status flag O_NONBLOCK is
dnl available, can be compiled, and seems to work. If
dnl all of these are true, then HAVE_FCNTL_O_NONBLOCK
dnl will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FCNTL_O_NONBLOCK], [
  #
  tst_compi_fcntl_o_nonblock="unknown"
  tst_allow_fcntl_o_nonblock="unknown"
  #
  case $host_os in
    sunos4* | aix3* | beos*)
      dnl O_NONBLOCK does not work on these platforms
      curl_disallow_fcntl_o_nonblock="yes"
      ;;
  esac
  #
  if test "$curl_cv_func_fcntl" = "yes"; then
    AC_MSG_CHECKING([if fcntl O_NONBLOCK is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_fcntl
      ]],[[
        int flags = 0;
        if(0 != fcntl(0, F_SETFL, flags | O_NONBLOCK))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_fcntl_o_nonblock="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_fcntl_o_nonblock="no"
    ])
  fi
  #
  if test "$tst_compi_fcntl_o_nonblock" = "yes"; then
    AC_MSG_CHECKING([if fcntl O_NONBLOCK usage allowed])
    if test "x$curl_disallow_fcntl_o_nonblock" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fcntl_o_nonblock="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fcntl_o_nonblock="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fcntl O_NONBLOCK might be used])
  if test "$tst_compi_fcntl_o_nonblock" = "yes" &&
     test "$tst_allow_fcntl_o_nonblock" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FCNTL_O_NONBLOCK, 1,
      [Define to 1 if you have a working fcntl O_NONBLOCK function.])
    curl_cv_func_fcntl_o_nonblock="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fcntl_o_nonblock="no"
  fi
])


dnl CURL_CHECK_FUNC_FDOPEN
dnl -------------------------------------------------
dnl Verify if fdopen is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fdopen, then
dnl HAVE_FDOPEN will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FDOPEN], [
  AC_REQUIRE([CURL_INCLUDES_STDIO])dnl
  #
  tst_links_fdopen="unknown"
  tst_proto_fdopen="unknown"
  tst_compi_fdopen="unknown"
  tst_allow_fdopen="unknown"
  #
  AC_MSG_CHECKING([if fdopen can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fdopen])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fdopen="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fdopen="no"
  ])
  #
  if test "$tst_links_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen is prototyped])
    AC_EGREP_CPP([fdopen],[
      $curl_includes_stdio
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fdopen="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fdopen="no"
    ])
  fi
  #
  if test "$tst_proto_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdio
      ]],[[
        if(0 != fdopen(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_fdopen="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_fdopen="no"
    ])
  fi
  #
  if test "$tst_compi_fdopen" = "yes"; then
    AC_MSG_CHECKING([if fdopen usage allowed])
    if test "x$curl_disallow_fdopen" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fdopen="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fdopen="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fdopen might be used])
  if test "$tst_links_fdopen" = "yes" &&
     test "$tst_proto_fdopen" = "yes" &&
     test "$tst_compi_fdopen" = "yes" &&
     test "$tst_allow_fdopen" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FDOPEN, 1,
      [Define to 1 if you have the fdopen function.])
    curl_cv_func_fdopen="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fdopen="no"
  fi
])


dnl CURL_CHECK_FUNC_FGETXATTR
dnl -------------------------------------------------
dnl Verify if fgetxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fgetxattr, then
dnl HAVE_FGETXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FGETXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_fgetxattr="unknown"
  tst_proto_fgetxattr="unknown"
  tst_compi_fgetxattr="unknown"
  tst_allow_fgetxattr="unknown"
  tst_nargs_fgetxattr="unknown"
  #
  AC_MSG_CHECKING([if fgetxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fgetxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fgetxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fgetxattr="no"
  ])
  #
  if test "$tst_links_fgetxattr" = "yes"; then
    AC_MSG_CHECKING([if fgetxattr is prototyped])
    AC_EGREP_CPP([fgetxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fgetxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fgetxattr="no"
    ])
  fi
  #
  if test "$tst_proto_fgetxattr" = "yes"; then
    if test "$tst_nargs_fgetxattr" = "unknown"; then
      AC_MSG_CHECKING([if fgetxattr takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fgetxattr(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fgetxattr="yes"
        tst_nargs_fgetxattr="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fgetxattr="no"
      ])
    fi
    if test "$tst_nargs_fgetxattr" = "unknown"; then
      AC_MSG_CHECKING([if fgetxattr takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fgetxattr(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fgetxattr="yes"
        tst_nargs_fgetxattr="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fgetxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if fgetxattr is compilable])
    if test "$tst_compi_fgetxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_fgetxattr" = "yes"; then
    AC_MSG_CHECKING([if fgetxattr usage allowed])
    if test "x$curl_disallow_fgetxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fgetxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fgetxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fgetxattr might be used])
  if test "$tst_links_fgetxattr" = "yes" &&
     test "$tst_proto_fgetxattr" = "yes" &&
     test "$tst_compi_fgetxattr" = "yes" &&
     test "$tst_allow_fgetxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FGETXATTR, 1,
      [Define to 1 if you have the fgetxattr function.])
    dnl AC_DEFINE_UNQUOTED(FGETXATTR_ARGS, $tst_nargs_fgetxattr,
    dnl   [Specifies the number of arguments to fgetxattr])
    #
    if test "$tst_nargs_fgetxattr" -eq "4"; then
      AC_DEFINE(HAVE_FGETXATTR_4, 1, [fgetxattr() takes 4 args])
    elif test "$tst_nargs_fgetxattr" -eq "6"; then
      AC_DEFINE(HAVE_FGETXATTR_6, 1, [fgetxattr() takes 6 args])
    fi
    #
    curl_cv_func_fgetxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fgetxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_FLISTXATTR
dnl -------------------------------------------------
dnl Verify if flistxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_flistxattr, then
dnl HAVE_FLISTXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FLISTXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_flistxattr="unknown"
  tst_proto_flistxattr="unknown"
  tst_compi_flistxattr="unknown"
  tst_allow_flistxattr="unknown"
  tst_nargs_flistxattr="unknown"
  #
  AC_MSG_CHECKING([if flistxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([flistxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_flistxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_flistxattr="no"
  ])
  #
  if test "$tst_links_flistxattr" = "yes"; then
    AC_MSG_CHECKING([if flistxattr is prototyped])
    AC_EGREP_CPP([flistxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_flistxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_flistxattr="no"
    ])
  fi
  #
  if test "$tst_proto_flistxattr" = "yes"; then
    if test "$tst_nargs_flistxattr" = "unknown"; then
      AC_MSG_CHECKING([if flistxattr takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != flistxattr(0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_flistxattr="yes"
        tst_nargs_flistxattr="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_flistxattr="no"
      ])
    fi
    if test "$tst_nargs_flistxattr" = "unknown"; then
      AC_MSG_CHECKING([if flistxattr takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != flistxattr(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_flistxattr="yes"
        tst_nargs_flistxattr="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_flistxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if flistxattr is compilable])
    if test "$tst_compi_flistxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_flistxattr" = "yes"; then
    AC_MSG_CHECKING([if flistxattr usage allowed])
    if test "x$curl_disallow_flistxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_flistxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_flistxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if flistxattr might be used])
  if test "$tst_links_flistxattr" = "yes" &&
     test "$tst_proto_flistxattr" = "yes" &&
     test "$tst_compi_flistxattr" = "yes" &&
     test "$tst_allow_flistxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FLISTXATTR, 1,
      [Define to 1 if you have the flistxattr function.])
    dnl AC_DEFINE_UNQUOTED(FLISTXATTR_ARGS, $tst_nargs_flistxattr,
    dnl   [Specifies the number of arguments to flistxattr])
    #
    if test "$tst_nargs_flistxattr" -eq "3"; then
      AC_DEFINE(HAVE_FLISTXATTR_3, 1, [flistxattr() takes 3 args])
    elif test "$tst_nargs_flistxattr" -eq "4"; then
      AC_DEFINE(HAVE_FLISTXATTR_4, 1, [flistxattr() takes 4 args])
    fi
    #
    curl_cv_func_flistxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_flistxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_FREEADDRINFO
dnl -------------------------------------------------
dnl Verify if freeaddrinfo is available, prototyped,
dnl and can be compiled. If all of these are true,
dnl and usage has not been previously disallowed with
dnl shell variable curl_disallow_freeaddrinfo, then
dnl HAVE_FREEADDRINFO will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FREEADDRINFO], [
  AC_REQUIRE([CURL_INCLUDES_WS2TCPIP])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_freeaddrinfo="unknown"
  tst_proto_freeaddrinfo="unknown"
  tst_compi_freeaddrinfo="unknown"
  tst_allow_freeaddrinfo="unknown"
  #
  AC_MSG_CHECKING([if freeaddrinfo can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_ws2tcpip
      $curl_includes_sys_socket
      $curl_includes_netdb
    ]],[[
      freeaddrinfo(0);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_freeaddrinfo="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_freeaddrinfo="no"
  ])
  #
  if test "$tst_links_freeaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if freeaddrinfo is prototyped])
    AC_EGREP_CPP([freeaddrinfo],[
      $curl_includes_ws2tcpip
      $curl_includes_sys_socket
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_freeaddrinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_freeaddrinfo="no"
    ])
  fi
  #
  if test "$tst_proto_freeaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if freeaddrinfo is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_ws2tcpip
        $curl_includes_sys_socket
        $curl_includes_netdb
      ]],[[
        freeaddrinfo(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_freeaddrinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_freeaddrinfo="no"
    ])
  fi
  #
  if test "$tst_compi_freeaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if freeaddrinfo usage allowed])
    if test "x$curl_disallow_freeaddrinfo" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_freeaddrinfo="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_freeaddrinfo="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if freeaddrinfo might be used])
  if test "$tst_links_freeaddrinfo" = "yes" &&
     test "$tst_proto_freeaddrinfo" = "yes" &&
     test "$tst_compi_freeaddrinfo" = "yes" &&
     test "$tst_allow_freeaddrinfo" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FREEADDRINFO, 1,
      [Define to 1 if you have the freeaddrinfo function.])
    curl_cv_func_freeaddrinfo="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_freeaddrinfo="no"
  fi
])


dnl CURL_CHECK_FUNC_FREEIFADDRS
dnl -------------------------------------------------
dnl Verify if freeifaddrs is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_freeifaddrs, then
dnl HAVE_FREEIFADDRS will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FREEIFADDRS], [
  AC_REQUIRE([CURL_INCLUDES_IFADDRS])dnl
  #
  tst_links_freeifaddrs="unknown"
  tst_proto_freeifaddrs="unknown"
  tst_compi_freeifaddrs="unknown"
  tst_allow_freeifaddrs="unknown"
  #
  AC_MSG_CHECKING([if freeifaddrs can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([freeifaddrs])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_freeifaddrs="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_freeifaddrs="no"
  ])
  #
  if test "$tst_links_freeifaddrs" = "yes"; then
    AC_MSG_CHECKING([if freeifaddrs is prototyped])
    AC_EGREP_CPP([freeifaddrs],[
      $curl_includes_ifaddrs
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_freeifaddrs="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_freeifaddrs="no"
    ])
  fi
  #
  if test "$tst_proto_freeifaddrs" = "yes"; then
    AC_MSG_CHECKING([if freeifaddrs is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_ifaddrs
      ]],[[
        freeifaddrs(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_freeifaddrs="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_freeifaddrs="no"
    ])
  fi
  #
  if test "$tst_compi_freeifaddrs" = "yes"; then
    AC_MSG_CHECKING([if freeifaddrs usage allowed])
    if test "x$curl_disallow_freeifaddrs" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_freeifaddrs="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_freeifaddrs="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if freeifaddrs might be used])
  if test "$tst_links_freeifaddrs" = "yes" &&
     test "$tst_proto_freeifaddrs" = "yes" &&
     test "$tst_compi_freeifaddrs" = "yes" &&
     test "$tst_allow_freeifaddrs" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FREEIFADDRS, 1,
      [Define to 1 if you have the freeifaddrs function.])
    curl_cv_func_freeifaddrs="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_freeifaddrs="no"
  fi
])


dnl CURL_CHECK_FUNC_FREMOVEXATTR
dnl -------------------------------------------------
dnl Verify if fremovexattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fremovexattr, then
dnl HAVE_FREMOVEXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FREMOVEXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_fremovexattr="unknown"
  tst_proto_fremovexattr="unknown"
  tst_compi_fremovexattr="unknown"
  tst_allow_fremovexattr="unknown"
  tst_nargs_fremovexattr="unknown"
  #
  AC_MSG_CHECKING([if fremovexattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fremovexattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fremovexattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fremovexattr="no"
  ])
  #
  if test "$tst_links_fremovexattr" = "yes"; then
    AC_MSG_CHECKING([if fremovexattr is prototyped])
    AC_EGREP_CPP([fremovexattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fremovexattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fremovexattr="no"
    ])
  fi
  #
  if test "$tst_proto_fremovexattr" = "yes"; then
    if test "$tst_nargs_fremovexattr" = "unknown"; then
      AC_MSG_CHECKING([if fremovexattr takes 2 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fremovexattr(0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fremovexattr="yes"
        tst_nargs_fremovexattr="2"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fremovexattr="no"
      ])
    fi
    if test "$tst_nargs_fremovexattr" = "unknown"; then
      AC_MSG_CHECKING([if fremovexattr takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fremovexattr(0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fremovexattr="yes"
        tst_nargs_fremovexattr="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fremovexattr="no"
      ])
    fi
    AC_MSG_CHECKING([if fremovexattr is compilable])
    if test "$tst_compi_fremovexattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_fremovexattr" = "yes"; then
    AC_MSG_CHECKING([if fremovexattr usage allowed])
    if test "x$curl_disallow_fremovexattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fremovexattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fremovexattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fremovexattr might be used])
  if test "$tst_links_fremovexattr" = "yes" &&
     test "$tst_proto_fremovexattr" = "yes" &&
     test "$tst_compi_fremovexattr" = "yes" &&
     test "$tst_allow_fremovexattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FREMOVEXATTR, 1,
      [Define to 1 if you have the fremovexattr function.])
    dnl AC_DEFINE_UNQUOTED(FREMOVEXATTR_ARGS, $tst_nargs_fremovexattr,
    dnl   [Specifies the number of arguments to fremovexattr])
    #
    if test "$tst_nargs_fremovexattr" -eq "2"; then
      AC_DEFINE(HAVE_FREMOVEXATTR_2, 1, [fremovexattr() takes 2 args])
    elif test "$tst_nargs_fremovexattr" -eq "3"; then
      AC_DEFINE(HAVE_FREMOVEXATTR_3, 1, [fremovexattr() takes 3 args])
    fi
    #
    curl_cv_func_fremovexattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fremovexattr="no"
  fi
])


dnl CURL_CHECK_FUNC_FSETXATTR
dnl -------------------------------------------------
dnl Verify if fsetxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_fsetxattr, then
dnl HAVE_FSETXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FSETXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_fsetxattr="unknown"
  tst_proto_fsetxattr="unknown"
  tst_compi_fsetxattr="unknown"
  tst_allow_fsetxattr="unknown"
  tst_nargs_fsetxattr="unknown"
  #
  AC_MSG_CHECKING([if fsetxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([fsetxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_fsetxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_fsetxattr="no"
  ])
  #
  if test "$tst_links_fsetxattr" = "yes"; then
    AC_MSG_CHECKING([if fsetxattr is prototyped])
    AC_EGREP_CPP([fsetxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_fsetxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_fsetxattr="no"
    ])
  fi
  #
  if test "$tst_proto_fsetxattr" = "yes"; then
    if test "$tst_nargs_fsetxattr" = "unknown"; then
      AC_MSG_CHECKING([if fsetxattr takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fsetxattr(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fsetxattr="yes"
        tst_nargs_fsetxattr="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fsetxattr="no"
      ])
    fi
    if test "$tst_nargs_fsetxattr" = "unknown"; then
      AC_MSG_CHECKING([if fsetxattr takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != fsetxattr(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_fsetxattr="yes"
        tst_nargs_fsetxattr="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_fsetxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if fsetxattr is compilable])
    if test "$tst_compi_fsetxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_fsetxattr" = "yes"; then
    AC_MSG_CHECKING([if fsetxattr usage allowed])
    if test "x$curl_disallow_fsetxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_fsetxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_fsetxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if fsetxattr might be used])
  if test "$tst_links_fsetxattr" = "yes" &&
     test "$tst_proto_fsetxattr" = "yes" &&
     test "$tst_compi_fsetxattr" = "yes" &&
     test "$tst_allow_fsetxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FSETXATTR, 1,
      [Define to 1 if you have the fsetxattr function.])
    dnl AC_DEFINE_UNQUOTED(FSETXATTR_ARGS, $tst_nargs_fsetxattr,
    dnl   [Specifies the number of arguments to fsetxattr])
    #
    if test "$tst_nargs_fsetxattr" -eq "5"; then
      AC_DEFINE(HAVE_FSETXATTR_5, 1, [fsetxattr() takes 5 args])
    elif test "$tst_nargs_fsetxattr" -eq "6"; then
      AC_DEFINE(HAVE_FSETXATTR_6, 1, [fsetxattr() takes 6 args])
    fi
    #
    curl_cv_func_fsetxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_fsetxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_FTRUNCATE
dnl -------------------------------------------------
dnl Verify if ftruncate is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_ftruncate, then
dnl HAVE_FTRUNCATE will be defined.

AC_DEFUN([CURL_CHECK_FUNC_FTRUNCATE], [
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  #
  tst_links_ftruncate="unknown"
  tst_proto_ftruncate="unknown"
  tst_compi_ftruncate="unknown"
  tst_allow_ftruncate="unknown"
  #
  AC_MSG_CHECKING([if ftruncate can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([ftruncate])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ftruncate="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ftruncate="no"
  ])
  #
  if test "$tst_links_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate is prototyped])
    AC_EGREP_CPP([ftruncate],[
      $curl_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_ftruncate="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_ftruncate="no"
    ])
  fi
  #
  if test "$tst_proto_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_unistd
      ]],[[
        if(0 != ftruncate(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ftruncate="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ftruncate="no"
    ])
  fi
  #
  if test "$tst_compi_ftruncate" = "yes"; then
    AC_MSG_CHECKING([if ftruncate usage allowed])
    if test "x$curl_disallow_ftruncate" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ftruncate="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ftruncate="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ftruncate might be used])
  if test "$tst_links_ftruncate" = "yes" &&
     test "$tst_proto_ftruncate" = "yes" &&
     test "$tst_compi_ftruncate" = "yes" &&
     test "$tst_allow_ftruncate" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_FTRUNCATE, 1,
      [Define to 1 if you have the ftruncate function.])
    curl_cv_func_ftruncate="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ftruncate="no"
  fi
])


dnl CURL_CHECK_FUNC_GETADDRINFO
dnl -------------------------------------------------
dnl Verify if getaddrinfo is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_getaddrinfo, then
dnl HAVE_GETADDRINFO will be defined. Additionally when
dnl HAVE_GETADDRINFO gets defined this will also attempt
dnl to find out if getaddrinfo happens to be threadsafe,
dnl defining HAVE_GETADDRINFO_THREADSAFE when true.

AC_DEFUN([CURL_CHECK_FUNC_GETADDRINFO], [
  AC_REQUIRE([CURL_INCLUDES_WS2TCPIP])dnl
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  #
  tst_links_getaddrinfo="unknown"
  tst_proto_getaddrinfo="unknown"
  tst_compi_getaddrinfo="unknown"
  tst_works_getaddrinfo="unknown"
  tst_allow_getaddrinfo="unknown"
  tst_tsafe_getaddrinfo="unknown"
  #
  AC_MSG_CHECKING([if getaddrinfo can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_ws2tcpip
      $curl_includes_sys_socket
      $curl_includes_netdb
    ]],[[
      if(0 != getaddrinfo(0, 0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getaddrinfo="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getaddrinfo="no"
  ])
  #
  if test "$tst_links_getaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if getaddrinfo is prototyped])
    AC_EGREP_CPP([getaddrinfo],[
      $curl_includes_ws2tcpip
      $curl_includes_sys_socket
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getaddrinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getaddrinfo="no"
    ])
  fi
  #
  if test "$tst_proto_getaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if getaddrinfo is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_ws2tcpip
        $curl_includes_sys_socket
        $curl_includes_netdb
      ]],[[
        if(0 != getaddrinfo(0, 0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_getaddrinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_getaddrinfo="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_getaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if getaddrinfo seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_ws2tcpip
        $curl_includes_stdlib
        $curl_includes_string
        $curl_includes_sys_socket
        $curl_includes_netdb
      ]],[[
        struct addrinfo hints;
        struct addrinfo *ai = 0;
        int error;

        #ifdef HAVE_WINSOCK2_H
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa))
                exit(2);
        #endif

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo("127.0.0.1", 0, &hints, &ai);
        if(error || !ai)
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_getaddrinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_getaddrinfo="no"
    ])
  fi
  #
  if test "$tst_compi_getaddrinfo" = "yes" &&
    test "$tst_works_getaddrinfo" != "no"; then
    AC_MSG_CHECKING([if getaddrinfo usage allowed])
    if test "x$curl_disallow_getaddrinfo" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getaddrinfo="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getaddrinfo="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getaddrinfo might be used])
  if test "$tst_links_getaddrinfo" = "yes" &&
     test "$tst_proto_getaddrinfo" = "yes" &&
     test "$tst_compi_getaddrinfo" = "yes" &&
     test "$tst_allow_getaddrinfo" = "yes" &&
     test "$tst_works_getaddrinfo" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETADDRINFO, 1,
      [Define to 1 if you have a working getaddrinfo function.])
    curl_cv_func_getaddrinfo="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getaddrinfo="no"
    curl_cv_func_getaddrinfo_threadsafe="no"
  fi
  #
  if test "$curl_cv_func_getaddrinfo" = "yes"; then
    AC_MSG_CHECKING([if getaddrinfo is threadsafe])
    case $host_os in
      aix[[1234]].* | aix5.[[01]].*)
        dnl aix 5.1 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      aix*)
        dnl aix 5.2 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      darwin[[12345]].*)
        dnl darwin 5.0 and mac os x 10.1.X and older
        tst_tsafe_getaddrinfo="no"
        ;;
      darwin*)
        dnl darwin 6.0 and mac os x 10.2.X and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      freebsd[[1234]].* | freebsd5.[[1234]]*)
        dnl freebsd 5.4 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      freebsd*)
        dnl freebsd 5.5 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      hpux[[123456789]].* | hpux10.* | hpux11.0* | hpux11.10*)
        dnl hpux 11.10 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      hpux*)
        dnl hpux 11.11 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      netbsd[[123]].*)
        dnl netbsd 3.X and older
        tst_tsafe_getaddrinfo="no"
        ;;
      netbsd*)
        dnl netbsd 4.X and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      *bsd*)
        dnl All other bsd's
        tst_tsafe_getaddrinfo="no"
        ;;
      solaris2*)
        dnl solaris which have it
        tst_tsafe_getaddrinfo="yes"
        ;;
    esac
    if test "$tst_tsafe_getaddrinfo" = "unknown" &&
       test "$curl_cv_native_windows" = "yes"; then
      tst_tsafe_getaddrinfo="yes"
    fi
    if test "$tst_tsafe_getaddrinfo" = "unknown"; then
      CURL_CHECK_DEF_CC([h_errno], [
        $curl_includes_sys_socket
        $curl_includes_netdb
        ], [silent])
      if test "$curl_cv_have_def_h_errno" = "yes"; then
        tst_h_errno_macro="yes"
      else
        tst_h_errno_macro="no"
      fi
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_socket
          $curl_includes_netdb
        ]],[[
          h_errno = 2;
          if(0 != h_errno)
            return 1;
        ]])
      ],[
        tst_h_errno_modifiable_lvalue="yes"
      ],[
        tst_h_errno_modifiable_lvalue="no"
      ])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
        ]],[[
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200809L)
          return 0;
#elif defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 700)
          return 0;
#else
          force compilation error
#endif
        ]])
      ],[
        tst_h_errno_sbs_issue_7="yes"
      ],[
        tst_h_errno_sbs_issue_7="no"
      ])
      if test "$tst_h_errno_macro" = "no" &&
         test "$tst_h_errno_modifiable_lvalue" = "no" &&
         test "$tst_h_errno_sbs_issue_7" = "no"; then
        tst_tsafe_getaddrinfo="no"
      else
        tst_tsafe_getaddrinfo="yes"
      fi
    fi
    AC_MSG_RESULT([$tst_tsafe_getaddrinfo])
    if test "$tst_tsafe_getaddrinfo" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_GETADDRINFO_THREADSAFE, 1,
        [Define to 1 if the getaddrinfo function is threadsafe.])
      curl_cv_func_getaddrinfo_threadsafe="yes"
    else
      curl_cv_func_getaddrinfo_threadsafe="no"
    fi
  fi
])


dnl CURL_CHECK_FUNC_GETHOSTBYADDR
dnl -------------------------------------------------
dnl Verify if gethostbyaddr is available, prototyped,
dnl and can be compiled. If all of these are true,
dnl and usage has not been previously disallowed with
dnl shell variable curl_disallow_gethostbyaddr, then
dnl HAVE_GETHOSTBYADDR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETHOSTBYADDR], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_gethostbyaddr="unknown"
  tst_proto_gethostbyaddr="unknown"
  tst_compi_gethostbyaddr="unknown"
  tst_allow_gethostbyaddr="unknown"
  #
  AC_MSG_CHECKING([if gethostbyaddr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_netdb
    ]],[[
      if(0 != gethostbyaddr(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostbyaddr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostbyaddr="no"
  ])
  #
  if test "$tst_links_gethostbyaddr" = "yes"; then
    AC_MSG_CHECKING([if gethostbyaddr is prototyped])
    AC_EGREP_CPP([gethostbyaddr],[
      $curl_includes_winsock2
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostbyaddr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostbyaddr="no"
    ])
  fi
  #
  if test "$tst_proto_gethostbyaddr" = "yes"; then
    AC_MSG_CHECKING([if gethostbyaddr is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_netdb
      ]],[[
        if(0 != gethostbyaddr(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gethostbyaddr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gethostbyaddr="no"
    ])
  fi
  #
  if test "$tst_compi_gethostbyaddr" = "yes"; then
    AC_MSG_CHECKING([if gethostbyaddr usage allowed])
    if test "x$curl_disallow_gethostbyaddr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostbyaddr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostbyaddr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostbyaddr might be used])
  if test "$tst_links_gethostbyaddr" = "yes" &&
     test "$tst_proto_gethostbyaddr" = "yes" &&
     test "$tst_compi_gethostbyaddr" = "yes" &&
     test "$tst_allow_gethostbyaddr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTBYADDR, 1,
      [Define to 1 if you have the gethostbyaddr function.])
    curl_cv_func_gethostbyaddr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gethostbyaddr="no"
  fi
])

dnl CURL_CHECK_FUNC_GAI_STRERROR
dnl -------------------------------------------------
dnl Verify if gai_strerror is available, prototyped,
dnl and can be compiled. If all of these are true,
dnl and usage has not been previously disallowed with
dnl shell variable curl_disallow_gai_strerror, then
dnl HAVE_GAI_STRERROR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GAI_STRERROR], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_gai_strerror="unknown"
  tst_proto_gai_strerror="unknown"
  tst_compi_gai_strerror="unknown"
  tst_allow_gai_strerror="unknown"
  #
  AC_MSG_CHECKING([if gai_strerror can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_netdb
    ]],[[
      if(0 != gai_strerror(0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gai_strerror="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gai_strerror="no"
  ])
  #
  if test "$tst_links_gai_strerror" = "yes"; then
    AC_MSG_CHECKING([if gai_strerror is prototyped])
    AC_EGREP_CPP([gai_strerror],[
      $curl_includes_winsock2
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gai_strerror="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gai_strerror="no"
    ])
  fi
  #
  if test "$tst_proto_gai_strerror" = "yes"; then
    AC_MSG_CHECKING([if gai_strerror is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_netdb
      ]],[[
        if(0 != gai_strerror(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gai_strerror="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gai_strerror="no"
    ])
  fi
  #
  if test "$tst_compi_gai_strerror" = "yes"; then
    AC_MSG_CHECKING([if gai_strerror usage allowed])
    if test "x$curl_disallow_gai_strerror" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gai_strerror="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gai_strerror="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gai_strerror might be used])
  if test "$tst_links_gai_strerror" = "yes" &&
     test "$tst_proto_gai_strerror" = "yes" &&
     test "$tst_compi_gai_strerror" = "yes" &&
     test "$tst_allow_gai_strerror" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GAI_STRERROR, 1,
      [Define to 1 if you have the gai_strerror function.])
    curl_cv_func_gai_strerror="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gai_strerror="no"
  fi
])


dnl CURL_CHECK_FUNC_GETHOSTBYADDR_R
dnl -------------------------------------------------
dnl Verify if gethostbyaddr_r is available, prototyped,
dnl and can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_gethostbyaddr_r, then
dnl HAVE_GETHOSTBYADDR_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETHOSTBYADDR_R], [
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_gethostbyaddr_r="unknown"
  tst_proto_gethostbyaddr_r="unknown"
  tst_compi_gethostbyaddr_r="unknown"
  tst_allow_gethostbyaddr_r="unknown"
  tst_nargs_gethostbyaddr_r="unknown"
  #
  AC_MSG_CHECKING([if gethostbyaddr_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyaddr_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostbyaddr_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostbyaddr_r="no"
  ])
  #
  if test "$tst_links_gethostbyaddr_r" = "yes"; then
    AC_MSG_CHECKING([if gethostbyaddr_r is prototyped])
    AC_EGREP_CPP([gethostbyaddr_r],[
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostbyaddr_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostbyaddr_r="no"
    ])
  fi
  #
  if test "$tst_proto_gethostbyaddr_r" = "yes"; then
    if test "$tst_nargs_gethostbyaddr_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyaddr_r takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyaddr_r(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyaddr_r="yes"
        tst_nargs_gethostbyaddr_r="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyaddr_r="no"
      ])
    fi
    if test "$tst_nargs_gethostbyaddr_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyaddr_r takes 7 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyaddr_r="yes"
        tst_nargs_gethostbyaddr_r="7"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyaddr_r="no"
      ])
    fi
    if test "$tst_nargs_gethostbyaddr_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyaddr_r takes 8 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyaddr_r(0, 0, 0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyaddr_r="yes"
        tst_nargs_gethostbyaddr_r="8"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyaddr_r="no"
      ])
    fi
    AC_MSG_CHECKING([if gethostbyaddr_r is compilable])
    if test "$tst_compi_gethostbyaddr_r" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_gethostbyaddr_r" = "yes"; then
    AC_MSG_CHECKING([if gethostbyaddr_r usage allowed])
    if test "x$curl_disallow_gethostbyaddr_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostbyaddr_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostbyaddr_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostbyaddr_r might be used])
  if test "$tst_links_gethostbyaddr_r" = "yes" &&
     test "$tst_proto_gethostbyaddr_r" = "yes" &&
     test "$tst_compi_gethostbyaddr_r" = "yes" &&
     test "$tst_allow_gethostbyaddr_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTBYADDR_R, 1,
      [Define to 1 if you have the gethostbyaddr_r function.])
    dnl AC_DEFINE_UNQUOTED(GETHOSTBYADDR_R_ARGS, $tst_nargs_gethostbyaddr_r,
    dnl   [Specifies the number of arguments to gethostbyaddr_r])
    #
    if test "$tst_nargs_gethostbyaddr_r" -eq "5"; then
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_5, 1, [gethostbyaddr_r() takes 5 args])
    elif test "$tst_nargs_gethostbyaddr_r" -eq "7"; then
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_7, 1, [gethostbyaddr_r() takes 7 args])
    elif test "$tst_nargs_gethostbyaddr_r" -eq "8"; then
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_8, 1, [gethostbyaddr_r() takes 8 args])
    fi
    #
    curl_cv_func_gethostbyaddr_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gethostbyaddr_r="no"
  fi
])


dnl CURL_CHECK_FUNC_GETHOSTBYNAME
dnl -------------------------------------------------
dnl Verify if gethostbyname is available, prototyped,
dnl and can be compiled. If all of these are true,
dnl and usage has not been previously disallowed with
dnl shell variable curl_disallow_gethostbyname, then
dnl HAVE_GETHOSTBYNAME will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETHOSTBYNAME], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_gethostbyname="unknown"
  tst_proto_gethostbyname="unknown"
  tst_compi_gethostbyname="unknown"
  tst_allow_gethostbyname="unknown"
  #
  AC_MSG_CHECKING([if gethostbyname can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_netdb
    ]],[[
      if(0 != gethostbyname(0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostbyname="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostbyname="no"
  ])
  #
  if test "$tst_links_gethostbyname" = "yes"; then
    AC_MSG_CHECKING([if gethostbyname is prototyped])
    AC_EGREP_CPP([gethostbyname],[
      $curl_includes_winsock2
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostbyname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostbyname="no"
    ])
  fi
  #
  if test "$tst_proto_gethostbyname" = "yes"; then
    AC_MSG_CHECKING([if gethostbyname is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_netdb
      ]],[[
        if(0 != gethostbyname(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gethostbyname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gethostbyname="no"
    ])
  fi
  #
  if test "$tst_compi_gethostbyname" = "yes"; then
    AC_MSG_CHECKING([if gethostbyname usage allowed])
    if test "x$curl_disallow_gethostbyname" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostbyname="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostbyname="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostbyname might be used])
  if test "$tst_links_gethostbyname" = "yes" &&
     test "$tst_proto_gethostbyname" = "yes" &&
     test "$tst_compi_gethostbyname" = "yes" &&
     test "$tst_allow_gethostbyname" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTBYNAME, 1,
      [Define to 1 if you have the gethostbyname function.])
    curl_cv_func_gethostbyname="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gethostbyname="no"
  fi
])


dnl CURL_CHECK_FUNC_GETHOSTBYNAME_R
dnl -------------------------------------------------
dnl Verify if gethostbyname_r is available, prototyped,
dnl and can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_gethostbyname_r, then
dnl HAVE_GETHOSTBYNAME_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETHOSTBYNAME_R], [
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_gethostbyname_r="unknown"
  tst_proto_gethostbyname_r="unknown"
  tst_compi_gethostbyname_r="unknown"
  tst_allow_gethostbyname_r="unknown"
  tst_nargs_gethostbyname_r="unknown"
  #
  AC_MSG_CHECKING([if gethostbyname_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gethostbyname_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostbyname_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostbyname_r="no"
  ])
  #
  if test "$tst_links_gethostbyname_r" = "yes"; then
    AC_MSG_CHECKING([if gethostbyname_r is prototyped])
    AC_EGREP_CPP([gethostbyname_r],[
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostbyname_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostbyname_r="no"
    ])
  fi
  #
  if test "$tst_proto_gethostbyname_r" = "yes"; then
    if test "$tst_nargs_gethostbyname_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyname_r takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyname_r(0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyname_r="yes"
        tst_nargs_gethostbyname_r="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyname_r="no"
      ])
    fi
    if test "$tst_nargs_gethostbyname_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyname_r takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyname_r(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyname_r="yes"
        tst_nargs_gethostbyname_r="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyname_r="no"
      ])
    fi
    if test "$tst_nargs_gethostbyname_r" = "unknown"; then
      AC_MSG_CHECKING([if gethostbyname_r takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != gethostbyname_r(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_gethostbyname_r="yes"
        tst_nargs_gethostbyname_r="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_gethostbyname_r="no"
      ])
    fi
    AC_MSG_CHECKING([if gethostbyname_r is compilable])
    if test "$tst_compi_gethostbyname_r" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_gethostbyname_r" = "yes"; then
    AC_MSG_CHECKING([if gethostbyname_r usage allowed])
    if test "x$curl_disallow_gethostbyname_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostbyname_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostbyname_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostbyname_r might be used])
  if test "$tst_links_gethostbyname_r" = "yes" &&
     test "$tst_proto_gethostbyname_r" = "yes" &&
     test "$tst_compi_gethostbyname_r" = "yes" &&
     test "$tst_allow_gethostbyname_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTBYNAME_R, 1,
      [Define to 1 if you have the gethostbyname_r function.])
    dnl AC_DEFINE_UNQUOTED(GETHOSTBYNAME_R_ARGS, $tst_nargs_gethostbyname_r,
    dnl   [Specifies the number of arguments to gethostbyname_r])
    #
    if test "$tst_nargs_gethostbyname_r" -eq "3"; then
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_3, 1, [gethostbyname_r() takes 3 args])
    elif test "$tst_nargs_gethostbyname_r" -eq "5"; then
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_5, 1, [gethostbyname_r() takes 5 args])
    elif test "$tst_nargs_gethostbyname_r" -eq "6"; then
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_6, 1, [gethostbyname_r() takes 6 args])
    fi
    #
    curl_cv_func_gethostbyname_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gethostbyname_r="no"
  fi
])


dnl CURL_CHECK_FUNC_GETHOSTNAME
dnl -------------------------------------------------
dnl Verify if gethostname is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_gethostname, then
dnl HAVE_GETHOSTNAME will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETHOSTNAME], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  AC_REQUIRE([CURL_PREPROCESS_CALLCONV])dnl
  #
  tst_links_gethostname="unknown"
  tst_proto_gethostname="unknown"
  tst_compi_gethostname="unknown"
  tst_allow_gethostname="unknown"
  #
  AC_MSG_CHECKING([if gethostname can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_unistd
    ]],[[
      if(0 != gethostname(0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gethostname="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gethostname="no"
  ])
  #
  if test "$tst_links_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname is prototyped])
    AC_EGREP_CPP([gethostname],[
      $curl_includes_winsock2
      $curl_includes_unistd
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gethostname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gethostname="no"
    ])
  fi
  #
  if test "$tst_proto_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_unistd
      ]],[[
        if(0 != gethostname(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gethostname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gethostname="no"
    ])
  fi
  #
  if test "$tst_compi_gethostname" = "yes"; then
    AC_MSG_CHECKING([for gethostname arg 2 data type])
    tst_gethostname_type_arg2="unknown"
    for tst_arg1 in 'char *' 'unsigned char *' 'void *'; do
      for tst_arg2 in 'int' 'unsigned int' 'size_t'; do
        if test "$tst_gethostname_type_arg2" = "unknown"; then
          AC_COMPILE_IFELSE([
            AC_LANG_PROGRAM([[
              $curl_includes_winsock2
              $curl_includes_unistd
              $curl_preprocess_callconv
              extern int FUNCALLCONV gethostname($tst_arg1, $tst_arg2);
            ]],[[
              if(0 != gethostname(0, 0))
                return 1;
            ]])
          ],[
            tst_gethostname_type_arg2="$tst_arg2"
          ])
        fi
      done
    done
    AC_MSG_RESULT([$tst_gethostname_type_arg2])
    if test "$tst_gethostname_type_arg2" != "unknown"; then
      AC_DEFINE_UNQUOTED(GETHOSTNAME_TYPE_ARG2, $tst_gethostname_type_arg2,
        [Define to the type of arg 2 for gethostname.])
    fi
  fi
  #
  if test "$tst_compi_gethostname" = "yes"; then
    AC_MSG_CHECKING([if gethostname usage allowed])
    if test "x$curl_disallow_gethostname" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gethostname="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gethostname="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gethostname might be used])
  if test "$tst_links_gethostname" = "yes" &&
     test "$tst_proto_gethostname" = "yes" &&
     test "$tst_compi_gethostname" = "yes" &&
     test "$tst_allow_gethostname" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETHOSTNAME, 1,
      [Define to 1 if you have the gethostname function.])
    curl_cv_func_gethostname="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gethostname="no"
  fi
])


dnl CURL_CHECK_FUNC_GETIFADDRS
dnl -------------------------------------------------
dnl Verify if getifaddrs is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_getifaddrs, then
dnl HAVE_GETIFADDRS will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETIFADDRS], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_IFADDRS])dnl
  #
  tst_links_getifaddrs="unknown"
  tst_proto_getifaddrs="unknown"
  tst_compi_getifaddrs="unknown"
  tst_works_getifaddrs="unknown"
  tst_allow_getifaddrs="unknown"
  #
  AC_MSG_CHECKING([if getifaddrs can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getifaddrs])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getifaddrs="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getifaddrs="no"
  ])
  #
  if test "$tst_links_getifaddrs" = "yes"; then
    AC_MSG_CHECKING([if getifaddrs is prototyped])
    AC_EGREP_CPP([getifaddrs],[
      $curl_includes_ifaddrs
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getifaddrs="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getifaddrs="no"
    ])
  fi
  #
  if test "$tst_proto_getifaddrs" = "yes"; then
    AC_MSG_CHECKING([if getifaddrs is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_ifaddrs
      ]],[[
        if(0 != getifaddrs(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_getifaddrs="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_getifaddrs="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_getifaddrs" = "yes"; then
    AC_MSG_CHECKING([if getifaddrs seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_ifaddrs
      ]],[[
        struct ifaddrs *ifa = 0;
        int error;

        error = getifaddrs(&ifa);
        if(error || !ifa)
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_getifaddrs="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_getifaddrs="no"
    ])
  fi
  #
  if test "$tst_compi_getifaddrs" = "yes" &&
    test "$tst_works_getifaddrs" != "no"; then
    AC_MSG_CHECKING([if getifaddrs usage allowed])
    if test "x$curl_disallow_getifaddrs" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getifaddrs="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getifaddrs="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getifaddrs might be used])
  if test "$tst_links_getifaddrs" = "yes" &&
     test "$tst_proto_getifaddrs" = "yes" &&
     test "$tst_compi_getifaddrs" = "yes" &&
     test "$tst_allow_getifaddrs" = "yes" &&
     test "$tst_works_getifaddrs" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETIFADDRS, 1,
      [Define to 1 if you have a working getifaddrs function.])
    curl_cv_func_getifaddrs="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getifaddrs="no"
  fi
])


dnl CURL_CHECK_FUNC_GETSERVBYPORT_R
dnl -------------------------------------------------
dnl Verify if getservbyport_r is available, prototyped,
dnl and can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_getservbyport_r, then
dnl HAVE_GETSERVBYPORT_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETSERVBYPORT_R], [
  AC_REQUIRE([CURL_INCLUDES_NETDB])dnl
  #
  tst_links_getservbyport_r="unknown"
  tst_proto_getservbyport_r="unknown"
  tst_compi_getservbyport_r="unknown"
  tst_allow_getservbyport_r="unknown"
  tst_nargs_getservbyport_r="unknown"
  #
  AC_MSG_CHECKING([if getservbyport_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getservbyport_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getservbyport_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getservbyport_r="no"
  ])
  #
  if test "$tst_links_getservbyport_r" = "yes"; then
    AC_MSG_CHECKING([if getservbyport_r is prototyped])
    AC_EGREP_CPP([getservbyport_r],[
      $curl_includes_netdb
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getservbyport_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getservbyport_r="no"
    ])
  fi
  #
  if test "$tst_proto_getservbyport_r" = "yes"; then
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    if test "$tst_nargs_getservbyport_r" = "unknown"; then
      AC_MSG_CHECKING([if getservbyport_r takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_netdb
        ]],[[
          if(0 != getservbyport_r(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getservbyport_r="yes"
        tst_nargs_getservbyport_r="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getservbyport_r="no"
      ])
    fi
    AC_MSG_CHECKING([if getservbyport_r is compilable])
    if test "$tst_compi_getservbyport_r" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_getservbyport_r" = "yes"; then
    AC_MSG_CHECKING([if getservbyport_r usage allowed])
    if test "x$curl_disallow_getservbyport_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getservbyport_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getservbyport_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getservbyport_r might be used])
  if test "$tst_links_getservbyport_r" = "yes" &&
     test "$tst_proto_getservbyport_r" = "yes" &&
     test "$tst_compi_getservbyport_r" = "yes" &&
     test "$tst_allow_getservbyport_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETSERVBYPORT_R, 1,
      [Define to 1 if you have the getservbyport_r function.])
    AC_DEFINE_UNQUOTED(GETSERVBYPORT_R_ARGS, $tst_nargs_getservbyport_r,
      [Specifies the number of arguments to getservbyport_r])
    if test "$tst_nargs_getservbyport_r" -eq "4"; then
      AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, sizeof(struct servent_data),
        [Specifies the size of the buffer to pass to getservbyport_r])
    else
      AC_DEFINE(GETSERVBYPORT_R_BUFSIZE, 4096,
        [Specifies the size of the buffer to pass to getservbyport_r])
    fi
    curl_cv_func_getservbyport_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getservbyport_r="no"
  fi
])


dnl CURL_CHECK_FUNC_GETXATTR
dnl -------------------------------------------------
dnl Verify if getxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_getxattr, then
dnl HAVE_GETXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_getxattr="unknown"
  tst_proto_getxattr="unknown"
  tst_compi_getxattr="unknown"
  tst_allow_getxattr="unknown"
  tst_nargs_getxattr="unknown"
  #
  AC_MSG_CHECKING([if getxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([getxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getxattr="no"
  ])
  #
  if test "$tst_links_getxattr" = "yes"; then
    AC_MSG_CHECKING([if getxattr is prototyped])
    AC_EGREP_CPP([getxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getxattr="no"
    ])
  fi
  #
  if test "$tst_proto_getxattr" = "yes"; then
    if test "$tst_nargs_getxattr" = "unknown"; then
      AC_MSG_CHECKING([if getxattr takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != getxattr(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getxattr="yes"
        tst_nargs_getxattr="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getxattr="no"
      ])
    fi
    if test "$tst_nargs_getxattr" = "unknown"; then
      AC_MSG_CHECKING([if getxattr takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != getxattr(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_getxattr="yes"
        tst_nargs_getxattr="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_getxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if getxattr is compilable])
    if test "$tst_compi_getxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_getxattr" = "yes"; then
    AC_MSG_CHECKING([if getxattr usage allowed])
    if test "x$curl_disallow_getxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getxattr might be used])
  if test "$tst_links_getxattr" = "yes" &&
     test "$tst_proto_getxattr" = "yes" &&
     test "$tst_compi_getxattr" = "yes" &&
     test "$tst_allow_getxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETXATTR, 1,
      [Define to 1 if you have the getxattr function.])
    dnl AC_DEFINE_UNQUOTED(GETXATTR_ARGS, $tst_nargs_getxattr,
    dnl   [Specifies the number of arguments to getxattr])
    #
    if test "$tst_nargs_getxattr" -eq "4"; then
      AC_DEFINE(HAVE_GETXATTR_4, 1, [getxattr() takes 4 args])
    elif test "$tst_nargs_getxattr" -eq "6"; then
      AC_DEFINE(HAVE_GETXATTR_6, 1, [getxattr() takes 6 args])
    fi
    #
    curl_cv_func_getxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_GMTIME_R
dnl -------------------------------------------------
dnl Verify if gmtime_r is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_gmtime_r, then
dnl HAVE_GMTIME_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GMTIME_R], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_TIME])dnl
  #
  tst_links_gmtime_r="unknown"
  tst_proto_gmtime_r="unknown"
  tst_compi_gmtime_r="unknown"
  tst_works_gmtime_r="unknown"
  tst_allow_gmtime_r="unknown"
  #
  AC_MSG_CHECKING([if gmtime_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gmtime_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_gmtime_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_gmtime_r="no"
  ])
  #
  if test "$tst_links_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r is prototyped])
    AC_EGREP_CPP([gmtime_r],[
      $curl_includes_time
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_gmtime_r="no"
    ])
  fi
  #
  if test "$tst_proto_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_time
      ]],[[
        if(0 != gmtime_r(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_gmtime_r="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_gmtime_r" = "yes"; then
    AC_MSG_CHECKING([if gmtime_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_time
      ]],[[
        time_t local = 1170352587;
        struct tm *gmt = 0;
        struct tm result;
        gmt = gmtime_r(&local, &result);
        if(gmt)
          exit(0);
        else
          exit(1);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_gmtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_gmtime_r="no"
    ])
  fi
  #
  if test "$tst_compi_gmtime_r" = "yes" &&
    test "$tst_works_gmtime_r" != "no"; then
    AC_MSG_CHECKING([if gmtime_r usage allowed])
    if test "x$curl_disallow_gmtime_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_gmtime_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_gmtime_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if gmtime_r might be used])
  if test "$tst_links_gmtime_r" = "yes" &&
     test "$tst_proto_gmtime_r" = "yes" &&
     test "$tst_compi_gmtime_r" = "yes" &&
     test "$tst_allow_gmtime_r" = "yes" &&
     test "$tst_works_gmtime_r" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GMTIME_R, 1,
      [Define to 1 if you have a working gmtime_r function.])
    curl_cv_func_gmtime_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_gmtime_r="no"
  fi
])


dnl CURL_CHECK_FUNC_INET_NTOA_R
dnl -------------------------------------------------
dnl Verify if inet_ntoa_r is available, prototyped,
dnl and can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_inet_ntoa_r, then
dnl HAVE_INET_NTOA_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_INET_NTOA_R], [
  AC_REQUIRE([CURL_INCLUDES_ARPA_INET])dnl
  #
  tst_links_inet_ntoa_r="unknown"
  tst_proto_inet_ntoa_r="unknown"
  tst_compi_inet_ntoa_r="unknown"
  tst_allow_inet_ntoa_r="unknown"
  tst_nargs_inet_ntoa_r="unknown"
  #
  AC_MSG_CHECKING([if inet_ntoa_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([inet_ntoa_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_inet_ntoa_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_inet_ntoa_r="no"
  ])
  #
  if test "$tst_links_inet_ntoa_r" = "yes"; then
    AC_MSG_CHECKING([if inet_ntoa_r is prototyped])
    AC_EGREP_CPP([inet_ntoa_r],[
      $curl_includes_arpa_inet
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_inet_ntoa_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_inet_ntoa_r="no"
    ])
  fi
  #
  if test "$tst_proto_inet_ntoa_r" = "yes"; then
    if test "$tst_nargs_inet_ntoa_r" = "unknown"; then
      AC_MSG_CHECKING([if inet_ntoa_r takes 2 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_arpa_inet
        ]],[[
          struct in_addr addr;
          if(0 != inet_ntoa_r(addr, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_inet_ntoa_r="yes"
        tst_nargs_inet_ntoa_r="2"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_inet_ntoa_r="no"
      ])
    fi
    if test "$tst_nargs_inet_ntoa_r" = "unknown"; then
      AC_MSG_CHECKING([if inet_ntoa_r takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_arpa_inet
        ]],[[
          struct in_addr addr;
          if(0 != inet_ntoa_r(addr, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_inet_ntoa_r="yes"
        tst_nargs_inet_ntoa_r="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_inet_ntoa_r="no"
      ])
    fi
    AC_MSG_CHECKING([if inet_ntoa_r is compilable])
    if test "$tst_compi_inet_ntoa_r" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_inet_ntoa_r" = "yes"; then
    AC_MSG_CHECKING([if inet_ntoa_r usage allowed])
    if test "x$curl_disallow_inet_ntoa_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_inet_ntoa_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_inet_ntoa_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if inet_ntoa_r might be used])
  if test "$tst_links_inet_ntoa_r" = "yes" &&
     test "$tst_proto_inet_ntoa_r" = "yes" &&
     test "$tst_compi_inet_ntoa_r" = "yes" &&
     test "$tst_allow_inet_ntoa_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_INET_NTOA_R, 1,
      [Define to 1 if you have the inet_ntoa_r function.])
    dnl AC_DEFINE_UNQUOTED(INET_NTOA_R_ARGS, $tst_nargs_inet_ntoa_r,
    dnl   [Specifies the number of arguments to inet_ntoa_r])
    #
    if test "$tst_nargs_inet_ntoa_r" -eq "2"; then
      AC_DEFINE(HAVE_INET_NTOA_R_2, 1, [inet_ntoa_r() takes 2 args])
    elif test "$tst_nargs_inet_ntoa_r" -eq "3"; then
      AC_DEFINE(HAVE_INET_NTOA_R_3, 1, [inet_ntoa_r() takes 3 args])
    fi
    #
    curl_cv_func_inet_ntoa_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_inet_ntoa_r="no"
  fi
])


dnl CURL_CHECK_FUNC_INET_NTOP
dnl -------------------------------------------------
dnl Verify if inet_ntop is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_inet_ntop, then
dnl HAVE_INET_NTOP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_INET_NTOP], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_ARPA_INET])dnl
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_inet_ntop="unknown"
  tst_proto_inet_ntop="unknown"
  tst_compi_inet_ntop="unknown"
  tst_works_inet_ntop="unknown"
  tst_allow_inet_ntop="unknown"
  #
  AC_MSG_CHECKING([if inet_ntop can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([inet_ntop])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_inet_ntop="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_inet_ntop="no"
  ])
  #
  if test "$tst_links_inet_ntop" = "yes"; then
    AC_MSG_CHECKING([if inet_ntop is prototyped])
    AC_EGREP_CPP([inet_ntop],[
      $curl_includes_arpa_inet
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_inet_ntop="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_inet_ntop="no"
    ])
  fi
  #
  if test "$tst_proto_inet_ntop" = "yes"; then
    AC_MSG_CHECKING([if inet_ntop is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_arpa_inet
      ]],[[
        if(0 != inet_ntop(0, 0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_inet_ntop="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_inet_ntop="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_inet_ntop" = "yes"; then
    AC_MSG_CHECKING([if inet_ntop seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_arpa_inet
        $curl_includes_string
      ]],[[
        char ipv6res[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
        char ipv4res[sizeof "255.255.255.255"];
        unsigned char ipv6a[26];
        unsigned char ipv4a[5];
        char *ipv6ptr = 0;
        char *ipv4ptr = 0;
        /* - */
        ipv4res[0] = '\0';
        ipv4a[0] = 0xc0;
        ipv4a[1] = 0xa8;
        ipv4a[2] = 0x64;
        ipv4a[3] = 0x01;
        ipv4a[4] = 0x01;
        /* - */
        ipv4ptr = inet_ntop(AF_INET, ipv4a, ipv4res, sizeof(ipv4res));
        if(!ipv4ptr)
          exit(1); /* fail */
        if(ipv4ptr != ipv4res)
          exit(1); /* fail */
        if(!ipv4ptr[0])
          exit(1); /* fail */
        if(memcmp(ipv4res, "192.168.100.1", 13) != 0)
          exit(1); /* fail */
        /* - */
        ipv6res[0] = '\0';
        memset(ipv6a, 0, sizeof(ipv6a));
        ipv6a[0] = 0xfe;
        ipv6a[1] = 0x80;
        ipv6a[8] = 0x02;
        ipv6a[9] = 0x14;
        ipv6a[10] = 0x4f;
        ipv6a[11] = 0xff;
        ipv6a[12] = 0xfe;
        ipv6a[13] = 0x0b;
        ipv6a[14] = 0x76;
        ipv6a[15] = 0xc8;
        ipv6a[25] = 0x01;
        /* - */
        ipv6ptr = inet_ntop(AF_INET6, ipv6a, ipv6res, sizeof(ipv6res));
        if(!ipv6ptr)
          exit(1); /* fail */
        if(ipv6ptr != ipv6res)
          exit(1); /* fail */
        if(!ipv6ptr[0])
          exit(1); /* fail */
        if(memcmp(ipv6res, "fe80::214:4fff:fe0b:76c8", 24) != 0)
          exit(1); /* fail */
        /* - */
        exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_inet_ntop="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_inet_ntop="no"
    ])
  fi
  #
  if test "$tst_compi_inet_ntop" = "yes" &&
    test "$tst_works_inet_ntop" != "no"; then
    AC_MSG_CHECKING([if inet_ntop usage allowed])
    if test "x$curl_disallow_inet_ntop" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_inet_ntop="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_inet_ntop="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if inet_ntop might be used])
  if test "$tst_links_inet_ntop" = "yes" &&
     test "$tst_proto_inet_ntop" = "yes" &&
     test "$tst_compi_inet_ntop" = "yes" &&
     test "$tst_allow_inet_ntop" = "yes" &&
     test "$tst_works_inet_ntop" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_INET_NTOP, 1,
      [Define to 1 if you have a IPv6 capable working inet_ntop function.])
    curl_cv_func_inet_ntop="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_inet_ntop="no"
  fi
])


dnl CURL_CHECK_FUNC_INET_PTON
dnl -------------------------------------------------
dnl Verify if inet_pton is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_inet_pton, then
dnl HAVE_INET_PTON will be defined.

AC_DEFUN([CURL_CHECK_FUNC_INET_PTON], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_ARPA_INET])dnl
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_inet_pton="unknown"
  tst_proto_inet_pton="unknown"
  tst_compi_inet_pton="unknown"
  tst_works_inet_pton="unknown"
  tst_allow_inet_pton="unknown"
  #
  AC_MSG_CHECKING([if inet_pton can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([inet_pton])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_inet_pton="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_inet_pton="no"
  ])
  #
  if test "$tst_links_inet_pton" = "yes"; then
    AC_MSG_CHECKING([if inet_pton is prototyped])
    AC_EGREP_CPP([inet_pton],[
      $curl_includes_arpa_inet
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_inet_pton="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_inet_pton="no"
    ])
  fi
  #
  if test "$tst_proto_inet_pton" = "yes"; then
    AC_MSG_CHECKING([if inet_pton is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_arpa_inet
      ]],[[
        if(0 != inet_pton(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_inet_pton="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_inet_pton="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_inet_pton" = "yes"; then
    AC_MSG_CHECKING([if inet_pton seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_arpa_inet
        $curl_includes_string
      ]],[[
        unsigned char ipv6a[16+1];
        unsigned char ipv4a[4+1];
        const char *ipv6src = "fe80::214:4fff:fe0b:76c8";
        const char *ipv4src = "192.168.100.1";
        /* - */
        memset(ipv4a, 1, sizeof(ipv4a));
        if(1 != inet_pton(AF_INET, ipv4src, ipv4a))
          exit(1); /* fail */
        /* - */
        if( (ipv4a[0] != 0xc0) ||
            (ipv4a[1] != 0xa8) ||
            (ipv4a[2] != 0x64) ||
            (ipv4a[3] != 0x01) ||
            (ipv4a[4] != 0x01) )
          exit(1); /* fail */
        /* - */
        memset(ipv6a, 1, sizeof(ipv6a));
        if(1 != inet_pton(AF_INET6, ipv6src, ipv6a))
          exit(1); /* fail */
        /* - */
        if( (ipv6a[0]  != 0xfe) ||
            (ipv6a[1]  != 0x80) ||
            (ipv6a[8]  != 0x02) ||
            (ipv6a[9]  != 0x14) ||
            (ipv6a[10] != 0x4f) ||
            (ipv6a[11] != 0xff) ||
            (ipv6a[12] != 0xfe) ||
            (ipv6a[13] != 0x0b) ||
            (ipv6a[14] != 0x76) ||
            (ipv6a[15] != 0xc8) ||
            (ipv6a[16] != 0x01) )
          exit(1); /* fail */
        /* - */
        if( (ipv6a[2]  != 0x0) ||
            (ipv6a[3]  != 0x0) ||
            (ipv6a[4]  != 0x0) ||
            (ipv6a[5]  != 0x0) ||
            (ipv6a[6]  != 0x0) ||
            (ipv6a[7]  != 0x0) )
          exit(1); /* fail */
        /* - */
        exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_inet_pton="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_inet_pton="no"
    ])
  fi
  #
  if test "$tst_compi_inet_pton" = "yes" &&
    test "$tst_works_inet_pton" != "no"; then
    AC_MSG_CHECKING([if inet_pton usage allowed])
    if test "x$curl_disallow_inet_pton" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_inet_pton="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_inet_pton="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if inet_pton might be used])
  if test "$tst_links_inet_pton" = "yes" &&
     test "$tst_proto_inet_pton" = "yes" &&
     test "$tst_compi_inet_pton" = "yes" &&
     test "$tst_allow_inet_pton" = "yes" &&
     test "$tst_works_inet_pton" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_INET_PTON, 1,
      [Define to 1 if you have a IPv6 capable working inet_pton function.])
    curl_cv_func_inet_pton="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_inet_pton="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTL
dnl -------------------------------------------------
dnl Verify if ioctl is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_ioctl, then
dnl HAVE_IOCTL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTL], [
  AC_REQUIRE([CURL_INCLUDES_STROPTS])dnl
  #
  tst_links_ioctl="unknown"
  tst_proto_ioctl="unknown"
  tst_compi_ioctl="unknown"
  tst_allow_ioctl="unknown"
  #
  AC_MSG_CHECKING([if ioctl can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([ioctl])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ioctl="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ioctl="no"
  ])
  #
  if test "$tst_links_ioctl" = "yes"; then
    AC_MSG_CHECKING([if ioctl is prototyped])
    AC_EGREP_CPP([ioctl],[
      $curl_includes_stropts
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_ioctl="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_ioctl="no"
    ])
  fi
  #
  if test "$tst_proto_ioctl" = "yes"; then
    AC_MSG_CHECKING([if ioctl is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stropts
      ]],[[
        if(0 != ioctl(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctl="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctl="no"
    ])
  fi
  #
  if test "$tst_compi_ioctl" = "yes"; then
    AC_MSG_CHECKING([if ioctl usage allowed])
    if test "x$curl_disallow_ioctl" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctl="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctl="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ioctl might be used])
  if test "$tst_links_ioctl" = "yes" &&
     test "$tst_proto_ioctl" = "yes" &&
     test "$tst_compi_ioctl" = "yes" &&
     test "$tst_allow_ioctl" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTL, 1,
      [Define to 1 if you have the ioctl function.])
    curl_cv_func_ioctl="yes"
    CURL_CHECK_FUNC_IOCTL_FIONBIO
    CURL_CHECK_FUNC_IOCTL_SIOCGIFADDR
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctl="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTL_FIONBIO
dnl -------------------------------------------------
dnl Verify if ioctl with the FIONBIO command is
dnl available, can be compiled, and seems to work. If
dnl all of these are true, then HAVE_IOCTL_FIONBIO
dnl will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTL_FIONBIO], [
  #
  tst_compi_ioctl_fionbio="unknown"
  tst_allow_ioctl_fionbio="unknown"
  #
  if test "$curl_cv_func_ioctl" = "yes"; then
    AC_MSG_CHECKING([if ioctl FIONBIO is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stropts
      ]],[[
        int flags = 0;
        if(0 != ioctl(0, FIONBIO, &flags))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctl_fionbio="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctl_fionbio="no"
    ])
  fi
  #
  if test "$tst_compi_ioctl_fionbio" = "yes"; then
    AC_MSG_CHECKING([if ioctl FIONBIO usage allowed])
    if test "x$curl_disallow_ioctl_fionbio" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctl_fionbio="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctl_fionbio="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ioctl FIONBIO might be used])
  if test "$tst_compi_ioctl_fionbio" = "yes" &&
     test "$tst_allow_ioctl_fionbio" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTL_FIONBIO, 1,
      [Define to 1 if you have a working ioctl FIONBIO function.])
    curl_cv_func_ioctl_fionbio="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctl_fionbio="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTL_SIOCGIFADDR
dnl -------------------------------------------------
dnl Verify if ioctl with the SIOCGIFADDR command is available,
dnl struct ifreq is defined, they can be compiled, and seem to
dnl work. If all of these are true, then HAVE_IOCTL_SIOCGIFADDR
dnl will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTL_SIOCGIFADDR], [
  #
  tst_compi_ioctl_siocgifaddr="unknown"
  tst_allow_ioctl_siocgifaddr="unknown"
  #
  if test "$curl_cv_func_ioctl" = "yes"; then
    AC_MSG_CHECKING([if ioctl SIOCGIFADDR is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stropts
        #include <net/if.h>
      ]],[[
        struct ifreq ifr;
        if(0 != ioctl(0, SIOCGIFADDR, &ifr))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctl_siocgifaddr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctl_siocgifaddr="no"
    ])
  fi
  #
  if test "$tst_compi_ioctl_siocgifaddr" = "yes"; then
    AC_MSG_CHECKING([if ioctl SIOCGIFADDR usage allowed])
    if test "x$curl_disallow_ioctl_siocgifaddr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctl_siocgifaddr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctl_siocgifaddr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ioctl SIOCGIFADDR might be used])
  if test "$tst_compi_ioctl_siocgifaddr" = "yes" &&
     test "$tst_allow_ioctl_siocgifaddr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTL_SIOCGIFADDR, 1,
      [Define to 1 if you have a working ioctl SIOCGIFADDR function.])
    curl_cv_func_ioctl_siocgifaddr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctl_siocgifaddr="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTLSOCKET
dnl -------------------------------------------------
dnl Verify if ioctlsocket is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_ioctlsocket, then
dnl HAVE_IOCTLSOCKET will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTLSOCKET], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  #
  tst_links_ioctlsocket="unknown"
  tst_proto_ioctlsocket="unknown"
  tst_compi_ioctlsocket="unknown"
  tst_allow_ioctlsocket="unknown"
  #
  AC_MSG_CHECKING([if ioctlsocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
    ]],[[
      if(0 != ioctlsocket(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ioctlsocket="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ioctlsocket="no"
  ])
  #
  if test "$tst_links_ioctlsocket" = "yes"; then
    AC_MSG_CHECKING([if ioctlsocket is prototyped])
    AC_EGREP_CPP([ioctlsocket],[
      $curl_includes_winsock2
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_ioctlsocket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_ioctlsocket="no"
    ])
  fi
  #
  if test "$tst_proto_ioctlsocket" = "yes"; then
    AC_MSG_CHECKING([if ioctlsocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
      ]],[[
        if(0 != ioctlsocket(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctlsocket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctlsocket="no"
    ])
  fi
  #
  if test "$tst_compi_ioctlsocket" = "yes"; then
    AC_MSG_CHECKING([if ioctlsocket usage allowed])
    if test "x$curl_disallow_ioctlsocket" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctlsocket="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctlsocket="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ioctlsocket might be used])
  if test "$tst_links_ioctlsocket" = "yes" &&
     test "$tst_proto_ioctlsocket" = "yes" &&
     test "$tst_compi_ioctlsocket" = "yes" &&
     test "$tst_allow_ioctlsocket" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTLSOCKET, 1,
      [Define to 1 if you have the ioctlsocket function.])
    curl_cv_func_ioctlsocket="yes"
    CURL_CHECK_FUNC_IOCTLSOCKET_FIONBIO
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctlsocket="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTLSOCKET_FIONBIO
dnl -------------------------------------------------
dnl Verify if ioctlsocket with the FIONBIO command is
dnl available, can be compiled, and seems to work. If
dnl all of these are true, then HAVE_IOCTLSOCKET_FIONBIO
dnl will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTLSOCKET_FIONBIO], [
  #
  tst_compi_ioctlsocket_fionbio="unknown"
  tst_allow_ioctlsocket_fionbio="unknown"
  #
  if test "$curl_cv_func_ioctlsocket" = "yes"; then
    AC_MSG_CHECKING([if ioctlsocket FIONBIO is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
      ]],[[
        int flags = 0;
        if(0 != ioctlsocket(0, FIONBIO, &flags))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctlsocket_fionbio="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctlsocket_fionbio="no"
    ])
  fi
  #
  if test "$tst_compi_ioctlsocket_fionbio" = "yes"; then
    AC_MSG_CHECKING([if ioctlsocket FIONBIO usage allowed])
    if test "x$curl_disallow_ioctlsocket_fionbio" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctlsocket_fionbio="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctlsocket_fionbio="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if ioctlsocket FIONBIO might be used])
  if test "$tst_compi_ioctlsocket_fionbio" = "yes" &&
     test "$tst_allow_ioctlsocket_fionbio" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTLSOCKET_FIONBIO, 1,
      [Define to 1 if you have a working ioctlsocket FIONBIO function.])
    curl_cv_func_ioctlsocket_fionbio="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctlsocket_fionbio="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL
dnl -------------------------------------------------
dnl Verify if IoctlSocket is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_ioctlsocket_camel,
dnl then HAVE_IOCTLSOCKET_CAMEL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL], [
  AC_REQUIRE([CURL_INCLUDES_STROPTS])dnl
  #
  tst_links_ioctlsocket_camel="unknown"
  tst_proto_ioctlsocket_camel="unknown"
  tst_compi_ioctlsocket_camel="unknown"
  tst_allow_ioctlsocket_camel="unknown"
  #
  AC_MSG_CHECKING([if IoctlSocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([IoctlSocket])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ioctlsocket_camel="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ioctlsocket_camel="no"
  ])
  #
  if test "$tst_links_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket is prototyped])
    AC_EGREP_CPP([IoctlSocket],[
      $curl_includes_stropts
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_ioctlsocket_camel="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_ioctlsocket_camel="no"
    ])
  fi
  #
  if test "$tst_proto_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stropts
      ]],[[
        if(0 != IoctlSocket(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctlsocket_camel="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctlsocket_camel="no"
    ])
  fi
  #
  if test "$tst_compi_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket usage allowed])
    if test "x$curl_disallow_ioctlsocket_camel" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctlsocket_camel="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctlsocket_camel="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if IoctlSocket might be used])
  if test "$tst_links_ioctlsocket_camel" = "yes" &&
     test "$tst_proto_ioctlsocket_camel" = "yes" &&
     test "$tst_compi_ioctlsocket_camel" = "yes" &&
     test "$tst_allow_ioctlsocket_camel" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTLSOCKET_CAMEL, 1,
      [Define to 1 if you have the IoctlSocket camel case function.])
    curl_cv_func_ioctlsocket_camel="yes"
    CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL_FIONBIO
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctlsocket_camel="no"
  fi
])


dnl CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL_FIONBIO
dnl -------------------------------------------------
dnl Verify if IoctlSocket with FIONBIO command is available,
dnl can be compiled, and seems to work. If all of these are
dnl true, then HAVE_IOCTLSOCKET_CAMEL_FIONBIO will be defined.

AC_DEFUN([CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL_FIONBIO], [
  #
  tst_compi_ioctlsocket_camel_fionbio="unknown"
  tst_allow_ioctlsocket_camel_fionbio="unknown"
  #
  if test "$curl_cv_func_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket FIONBIO is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stropts
      ]],[[
        long flags = 0;
        if(0 != ioctlsocket(0, FIONBIO, &flags))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_ioctlsocket_camel_fionbio="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_ioctlsocket_camel_fionbio="no"
    ])
  fi
  #
  if test "$tst_compi_ioctlsocket_camel_fionbio" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket FIONBIO usage allowed])
    if test "x$curl_disallow_ioctlsocket_camel_fionbio" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_ioctlsocket_camel_fionbio="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_ioctlsocket_camel_fionbio="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if IoctlSocket FIONBIO might be used])
  if test "$tst_compi_ioctlsocket_camel_fionbio" = "yes" &&
     test "$tst_allow_ioctlsocket_camel_fionbio" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_IOCTLSOCKET_CAMEL_FIONBIO, 1,
      [Define to 1 if you have a working IoctlSocket camel case FIONBIO function.])
    curl_cv_func_ioctlsocket_camel_fionbio="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_ioctlsocket_camel_fionbio="no"
  fi
])


dnl CURL_CHECK_FUNC_LISTXATTR
dnl -------------------------------------------------
dnl Verify if listxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_listxattr, then
dnl HAVE_LISTXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_LISTXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_listxattr="unknown"
  tst_proto_listxattr="unknown"
  tst_compi_listxattr="unknown"
  tst_allow_listxattr="unknown"
  tst_nargs_listxattr="unknown"
  #
  AC_MSG_CHECKING([if listxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([listxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_listxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_listxattr="no"
  ])
  #
  if test "$tst_links_listxattr" = "yes"; then
    AC_MSG_CHECKING([if listxattr is prototyped])
    AC_EGREP_CPP([listxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_listxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_listxattr="no"
    ])
  fi
  #
  if test "$tst_proto_listxattr" = "yes"; then
    if test "$tst_nargs_listxattr" = "unknown"; then
      AC_MSG_CHECKING([if listxattr takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != listxattr(0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_listxattr="yes"
        tst_nargs_listxattr="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_listxattr="no"
      ])
    fi
    if test "$tst_nargs_listxattr" = "unknown"; then
      AC_MSG_CHECKING([if listxattr takes 4 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != listxattr(0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_listxattr="yes"
        tst_nargs_listxattr="4"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_listxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if listxattr is compilable])
    if test "$tst_compi_listxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_listxattr" = "yes"; then
    AC_MSG_CHECKING([if listxattr usage allowed])
    if test "x$curl_disallow_listxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_listxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_listxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if listxattr might be used])
  if test "$tst_links_listxattr" = "yes" &&
     test "$tst_proto_listxattr" = "yes" &&
     test "$tst_compi_listxattr" = "yes" &&
     test "$tst_allow_listxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_LISTXATTR, 1,
      [Define to 1 if you have the listxattr function.])
    dnl AC_DEFINE_UNQUOTED(LISTXATTR_ARGS, $tst_nargs_listxattr,
    dnl   [Specifies the number of arguments to listxattr])
    #
    if test "$tst_nargs_listxattr" -eq "3"; then
      AC_DEFINE(HAVE_LISTXATTR_3, 1, [listxattr() takes 3 args])
    elif test "$tst_nargs_listxattr" -eq "4"; then
      AC_DEFINE(HAVE_LISTXATTR_4, 1, [listxattr() takes 4 args])
    fi
    #
    curl_cv_func_listxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_listxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_LOCALTIME_R
dnl -------------------------------------------------
dnl Verify if localtime_r is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_localtime_r, then
dnl HAVE_LOCALTIME_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_LOCALTIME_R], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_TIME])dnl
  #
  tst_links_localtime_r="unknown"
  tst_proto_localtime_r="unknown"
  tst_compi_localtime_r="unknown"
  tst_works_localtime_r="unknown"
  tst_allow_localtime_r="unknown"
  #
  AC_MSG_CHECKING([if localtime_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([localtime_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_localtime_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_localtime_r="no"
  ])
  #
  if test "$tst_links_localtime_r" = "yes"; then
    AC_MSG_CHECKING([if localtime_r is prototyped])
    AC_EGREP_CPP([localtime_r],[
      $curl_includes_time
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_localtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_localtime_r="no"
    ])
  fi
  #
  if test "$tst_proto_localtime_r" = "yes"; then
    AC_MSG_CHECKING([if localtime_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_time
      ]],[[
        if(0 != localtime_r(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_localtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_localtime_r="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_localtime_r" = "yes"; then
    AC_MSG_CHECKING([if localtime_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_time
      ]],[[
        time_t clock = 1170352587;
        struct tm *tmp = 0;
        struct tm result;
        tmp = localtime_r(&clock, &result);
        if(tmp)
          exit(0);
        else
          exit(1);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_localtime_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_localtime_r="no"
    ])
  fi
  #
  if test "$tst_compi_localtime_r" = "yes" &&
    test "$tst_works_localtime_r" != "no"; then
    AC_MSG_CHECKING([if localtime_r usage allowed])
    if test "x$curl_disallow_localtime_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_localtime_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_localtime_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if localtime_r might be used])
  if test "$tst_links_localtime_r" = "yes" &&
     test "$tst_proto_localtime_r" = "yes" &&
     test "$tst_compi_localtime_r" = "yes" &&
     test "$tst_allow_localtime_r" = "yes" &&
     test "$tst_works_localtime_r" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_LOCALTIME_R, 1,
      [Define to 1 if you have a working localtime_r function.])
    curl_cv_func_localtime_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_localtime_r="no"
  fi
])


dnl CURL_CHECK_FUNC_MEMRCHR
dnl -------------------------------------------------
dnl Verify if memrchr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_memrchr, then
dnl HAVE_MEMRCHR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_MEMRCHR], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_memrchr="unknown"
  tst_macro_memrchr="unknown"
  tst_proto_memrchr="unknown"
  tst_compi_memrchr="unknown"
  tst_allow_memrchr="unknown"
  #
  AC_MSG_CHECKING([if memrchr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([memrchr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_memrchr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_memrchr="no"
  ])
  #
  if test "$tst_links_memrchr" = "no"; then
    AC_MSG_CHECKING([if memrchr seems a macro])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != memrchr(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_macro_memrchr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_macro_memrchr="no"
    ])
  fi
  #
  if test "$tst_links_memrchr" = "yes"; then
    AC_MSG_CHECKING([if memrchr is prototyped])
    AC_EGREP_CPP([memrchr],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_memrchr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_memrchr="no"
    ])
  fi
  #
  if test "$tst_proto_memrchr" = "yes" ||
     test "$tst_macro_memrchr" = "yes"; then
    AC_MSG_CHECKING([if memrchr is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != memrchr(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_memrchr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_memrchr="no"
    ])
  fi
  #
  if test "$tst_compi_memrchr" = "yes"; then
    AC_MSG_CHECKING([if memrchr usage allowed])
    if test "x$curl_disallow_memrchr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_memrchr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_memrchr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if memrchr might be used])
  if (test "$tst_proto_memrchr" = "yes" ||
      test "$tst_macro_memrchr" = "yes") &&
     test "$tst_compi_memrchr" = "yes" &&
     test "$tst_allow_memrchr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_MEMRCHR, 1,
      [Define to 1 if you have the memrchr function or macro.])
    curl_cv_func_memrchr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_memrchr="no"
  fi
])


dnl CURL_CHECK_FUNC_POLL
dnl -------------------------------------------------
dnl Verify if poll is available, prototyped, can
dnl be compiled and seems to work. If all of these are
dnl true, and usage has not been previously disallowed
dnl with shell variable curl_disallow_poll, then
dnl HAVE_POLL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_POLL], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_POLL])dnl
  #
  tst_links_poll="unknown"
  tst_proto_poll="unknown"
  tst_compi_poll="unknown"
  tst_works_poll="unknown"
  tst_allow_poll="unknown"
  #
  case $host_os in
    darwin[[123456789]].*|darwin10.*|darwin11.*|darwin12.*|interix*)
      dnl poll() does not work on these platforms
      dnl Interix: "does provide poll(), but the implementing developer must
      dnl have been in a bad mood, because poll() only works on the /proc
      dnl filesystem here"
      curl_disallow_poll="yes"
      ;;
  esac
  #
  AC_MSG_CHECKING([if poll can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_poll
    ]],[[
      if(0 != poll(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_poll="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_poll="no"
  ])
  #
  if test "$tst_links_poll" = "yes"; then
    AC_MSG_CHECKING([if poll is prototyped])
    AC_EGREP_CPP([poll],[
      $curl_includes_poll
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_poll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_poll="no"
    ])
  fi
  #
  if test "$tst_proto_poll" = "yes"; then
    AC_MSG_CHECKING([if poll is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_poll
      ]],[[
        if(0 != poll(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_poll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_poll="no"
    ])
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_compi_poll" = "yes"; then
    AC_MSG_CHECKING([if poll seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_poll
      ]],[[
        if(0 != poll(0, 0, 10))
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_poll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_poll="no"
    ])
  fi
  #
  if test "$tst_compi_poll" = "yes" &&
    test "$tst_works_poll" != "no"; then
    AC_MSG_CHECKING([if poll usage allowed])
    if test "x$curl_disallow_poll" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_poll="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_poll="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if poll might be used])
  if test "$tst_links_poll" = "yes" &&
     test "$tst_proto_poll" = "yes" &&
     test "$tst_compi_poll" = "yes" &&
     test "$tst_allow_poll" = "yes" &&
     test "$tst_works_poll" != "no"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_POLL, 1,
      [Define to 1 if you have a working poll function.])
    AC_DEFINE_UNQUOTED(HAVE_POLL_FINE, 1,
      [If you have a fine poll])
    curl_cv_func_poll="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_poll="no"
  fi
])


dnl CURL_CHECK_FUNC_REMOVEXATTR
dnl -------------------------------------------------
dnl Verify if removexattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_removexattr, then
dnl HAVE_REMOVEXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_REMOVEXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_removexattr="unknown"
  tst_proto_removexattr="unknown"
  tst_compi_removexattr="unknown"
  tst_allow_removexattr="unknown"
  tst_nargs_removexattr="unknown"
  #
  AC_MSG_CHECKING([if removexattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([removexattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_removexattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_removexattr="no"
  ])
  #
  if test "$tst_links_removexattr" = "yes"; then
    AC_MSG_CHECKING([if removexattr is prototyped])
    AC_EGREP_CPP([removexattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_removexattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_removexattr="no"
    ])
  fi
  #
  if test "$tst_proto_removexattr" = "yes"; then
    if test "$tst_nargs_removexattr" = "unknown"; then
      AC_MSG_CHECKING([if removexattr takes 2 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != removexattr(0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_removexattr="yes"
        tst_nargs_removexattr="2"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_removexattr="no"
      ])
    fi
    if test "$tst_nargs_removexattr" = "unknown"; then
      AC_MSG_CHECKING([if removexattr takes 3 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != removexattr(0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_removexattr="yes"
        tst_nargs_removexattr="3"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_removexattr="no"
      ])
    fi
    AC_MSG_CHECKING([if removexattr is compilable])
    if test "$tst_compi_removexattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_removexattr" = "yes"; then
    AC_MSG_CHECKING([if removexattr usage allowed])
    if test "x$curl_disallow_removexattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_removexattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_removexattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if removexattr might be used])
  if test "$tst_links_removexattr" = "yes" &&
     test "$tst_proto_removexattr" = "yes" &&
     test "$tst_compi_removexattr" = "yes" &&
     test "$tst_allow_removexattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_REMOVEXATTR, 1,
      [Define to 1 if you have the removexattr function.])
    dnl AC_DEFINE_UNQUOTED(REMOVEXATTR_ARGS, $tst_nargs_removexattr,
    dnl   [Specifies the number of arguments to removexattr])
    #
    if test "$tst_nargs_removexattr" -eq "2"; then
      AC_DEFINE(HAVE_REMOVEXATTR_2, 1, [removexattr() takes 2 args])
    elif test "$tst_nargs_removexattr" -eq "3"; then
      AC_DEFINE(HAVE_REMOVEXATTR_3, 1, [removexattr() takes 3 args])
    fi
    #
    curl_cv_func_removexattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_removexattr="no"
  fi
])


dnl CURL_CHECK_FUNC_SETSOCKOPT
dnl -------------------------------------------------
dnl Verify if setsockopt is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_setsockopt, then
dnl HAVE_SETSOCKOPT will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SETSOCKOPT], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  #
  tst_links_setsockopt="unknown"
  tst_proto_setsockopt="unknown"
  tst_compi_setsockopt="unknown"
  tst_allow_setsockopt="unknown"
  #
  AC_MSG_CHECKING([if setsockopt can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_sys_socket
    ]],[[
      if(0 != setsockopt(0, 0, 0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_setsockopt="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_setsockopt="no"
  ])
  #
  if test "$tst_links_setsockopt" = "yes"; then
    AC_MSG_CHECKING([if setsockopt is prototyped])
    AC_EGREP_CPP([setsockopt],[
      $curl_includes_winsock2
      $curl_includes_sys_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_setsockopt="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_setsockopt="no"
    ])
  fi
  #
  if test "$tst_proto_setsockopt" = "yes"; then
    AC_MSG_CHECKING([if setsockopt is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_sys_socket
      ]],[[
        if(0 != setsockopt(0, 0, 0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_setsockopt="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_setsockopt="no"
    ])
  fi
  #
  if test "$tst_compi_setsockopt" = "yes"; then
    AC_MSG_CHECKING([if setsockopt usage allowed])
    if test "x$curl_disallow_setsockopt" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_setsockopt="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_setsockopt="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if setsockopt might be used])
  if test "$tst_links_setsockopt" = "yes" &&
     test "$tst_proto_setsockopt" = "yes" &&
     test "$tst_compi_setsockopt" = "yes" &&
     test "$tst_allow_setsockopt" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SETSOCKOPT, 1,
      [Define to 1 if you have the setsockopt function.])
    curl_cv_func_setsockopt="yes"
    CURL_CHECK_FUNC_SETSOCKOPT_SO_NONBLOCK
  else
    AC_MSG_RESULT([no])
    curl_cv_func_setsockopt="no"
  fi
])


dnl CURL_CHECK_FUNC_SETSOCKOPT_SO_NONBLOCK
dnl -------------------------------------------------
dnl Verify if setsockopt with the SO_NONBLOCK command is
dnl available, can be compiled, and seems to work. If
dnl all of these are true, then HAVE_SETSOCKOPT_SO_NONBLOCK
dnl will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SETSOCKOPT_SO_NONBLOCK], [
  #
  tst_compi_setsockopt_so_nonblock="unknown"
  tst_allow_setsockopt_so_nonblock="unknown"
  #
  if test "$curl_cv_func_setsockopt" = "yes"; then
    AC_MSG_CHECKING([if setsockopt SO_NONBLOCK is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_sys_socket
      ]],[[
        if(0 != setsockopt(0, SOL_SOCKET, SO_NONBLOCK, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_setsockopt_so_nonblock="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_setsockopt_so_nonblock="no"
    ])
  fi
  #
  if test "$tst_compi_setsockopt_so_nonblock" = "yes"; then
    AC_MSG_CHECKING([if setsockopt SO_NONBLOCK usage allowed])
    if test "x$curl_disallow_setsockopt_so_nonblock" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_setsockopt_so_nonblock="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_setsockopt_so_nonblock="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if setsockopt SO_NONBLOCK might be used])
  if test "$tst_compi_setsockopt_so_nonblock" = "yes" &&
     test "$tst_allow_setsockopt_so_nonblock" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SETSOCKOPT_SO_NONBLOCK, 1,
      [Define to 1 if you have a working setsockopt SO_NONBLOCK function.])
    curl_cv_func_setsockopt_so_nonblock="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_setsockopt_so_nonblock="no"
  fi
])


dnl CURL_CHECK_FUNC_SETXATTR
dnl -------------------------------------------------
dnl Verify if setxattr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_setxattr, then
dnl HAVE_SETXATTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SETXATTR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_XATTR])dnl
  #
  tst_links_setxattr="unknown"
  tst_proto_setxattr="unknown"
  tst_compi_setxattr="unknown"
  tst_allow_setxattr="unknown"
  tst_nargs_setxattr="unknown"
  #
  AC_MSG_CHECKING([if setxattr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([setxattr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_setxattr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_setxattr="no"
  ])
  #
  if test "$tst_links_setxattr" = "yes"; then
    AC_MSG_CHECKING([if setxattr is prototyped])
    AC_EGREP_CPP([setxattr],[
      $curl_includes_sys_xattr
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_setxattr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_setxattr="no"
    ])
  fi
  #
  if test "$tst_proto_setxattr" = "yes"; then
    if test "$tst_nargs_setxattr" = "unknown"; then
      AC_MSG_CHECKING([if setxattr takes 5 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != setxattr(0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_setxattr="yes"
        tst_nargs_setxattr="5"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_setxattr="no"
      ])
    fi
    if test "$tst_nargs_setxattr" = "unknown"; then
      AC_MSG_CHECKING([if setxattr takes 6 args.])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_xattr
        ]],[[
          if(0 != setxattr(0, 0, 0, 0, 0, 0))
            return 1;
        ]])
      ],[
        AC_MSG_RESULT([yes])
        tst_compi_setxattr="yes"
        tst_nargs_setxattr="6"
      ],[
        AC_MSG_RESULT([no])
        tst_compi_setxattr="no"
      ])
    fi
    AC_MSG_CHECKING([if setxattr is compilable])
    if test "$tst_compi_setxattr" = "yes"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi
  #
  if test "$tst_compi_setxattr" = "yes"; then
    AC_MSG_CHECKING([if setxattr usage allowed])
    if test "x$curl_disallow_setxattr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_setxattr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_setxattr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if setxattr might be used])
  if test "$tst_links_setxattr" = "yes" &&
     test "$tst_proto_setxattr" = "yes" &&
     test "$tst_compi_setxattr" = "yes" &&
     test "$tst_allow_setxattr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SETXATTR, 1,
      [Define to 1 if you have the setxattr function.])
    dnl AC_DEFINE_UNQUOTED(SETXATTR_ARGS, $tst_nargs_setxattr,
    dnl   [Specifies the number of arguments to setxattr])
    #
    if test "$tst_nargs_setxattr" -eq "5"; then
      AC_DEFINE(HAVE_SETXATTR_5, 1, [setxattr() takes 5 args])
    elif test "$tst_nargs_setxattr" -eq "6"; then
      AC_DEFINE(HAVE_SETXATTR_6, 1, [setxattr() takes 6 args])
    fi
    #
    curl_cv_func_setxattr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_setxattr="no"
  fi
])


dnl CURL_CHECK_FUNC_SIGACTION
dnl -------------------------------------------------
dnl Verify if sigaction is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_sigaction, then
dnl HAVE_SIGACTION will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SIGACTION], [
  AC_REQUIRE([CURL_INCLUDES_SIGNAL])dnl
  #
  tst_links_sigaction="unknown"
  tst_proto_sigaction="unknown"
  tst_compi_sigaction="unknown"
  tst_allow_sigaction="unknown"
  #
  AC_MSG_CHECKING([if sigaction can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([sigaction])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_sigaction="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_sigaction="no"
  ])
  #
  if test "$tst_links_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction is prototyped])
    AC_EGREP_CPP([sigaction],[
      $curl_includes_signal
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_sigaction="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_sigaction="no"
    ])
  fi
  #
  if test "$tst_proto_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_signal
      ]],[[
        if(0 != sigaction(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_sigaction="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_sigaction="no"
    ])
  fi
  #
  if test "$tst_compi_sigaction" = "yes"; then
    AC_MSG_CHECKING([if sigaction usage allowed])
    if test "x$curl_disallow_sigaction" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_sigaction="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_sigaction="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if sigaction might be used])
  if test "$tst_links_sigaction" = "yes" &&
     test "$tst_proto_sigaction" = "yes" &&
     test "$tst_compi_sigaction" = "yes" &&
     test "$tst_allow_sigaction" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SIGACTION, 1,
      [Define to 1 if you have the sigaction function.])
    curl_cv_func_sigaction="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_sigaction="no"
  fi
])


dnl CURL_CHECK_FUNC_SIGINTERRUPT
dnl -------------------------------------------------
dnl Verify if siginterrupt is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_siginterrupt, then
dnl HAVE_SIGINTERRUPT will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SIGINTERRUPT], [
  AC_REQUIRE([CURL_INCLUDES_SIGNAL])dnl
  #
  tst_links_siginterrupt="unknown"
  tst_proto_siginterrupt="unknown"
  tst_compi_siginterrupt="unknown"
  tst_allow_siginterrupt="unknown"
  #
  AC_MSG_CHECKING([if siginterrupt can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([siginterrupt])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_siginterrupt="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_siginterrupt="no"
  ])
  #
  if test "$tst_links_siginterrupt" = "yes"; then
    AC_MSG_CHECKING([if siginterrupt is prototyped])
    AC_EGREP_CPP([siginterrupt],[
      $curl_includes_signal
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_siginterrupt="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_siginterrupt="no"
    ])
  fi
  #
  if test "$tst_proto_siginterrupt" = "yes"; then
    AC_MSG_CHECKING([if siginterrupt is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_signal
      ]],[[
        if(0 != siginterrupt(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_siginterrupt="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_siginterrupt="no"
    ])
  fi
  #
  if test "$tst_compi_siginterrupt" = "yes"; then
    AC_MSG_CHECKING([if siginterrupt usage allowed])
    if test "x$curl_disallow_siginterrupt" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_siginterrupt="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_siginterrupt="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if siginterrupt might be used])
  if test "$tst_links_siginterrupt" = "yes" &&
     test "$tst_proto_siginterrupt" = "yes" &&
     test "$tst_compi_siginterrupt" = "yes" &&
     test "$tst_allow_siginterrupt" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SIGINTERRUPT, 1,
      [Define to 1 if you have the siginterrupt function.])
    curl_cv_func_siginterrupt="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_siginterrupt="no"
  fi
])


dnl CURL_CHECK_FUNC_SIGNAL
dnl -------------------------------------------------
dnl Verify if signal is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_signal, then
dnl HAVE_SIGNAL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SIGNAL], [
  AC_REQUIRE([CURL_INCLUDES_SIGNAL])dnl
  #
  tst_links_signal="unknown"
  tst_proto_signal="unknown"
  tst_compi_signal="unknown"
  tst_allow_signal="unknown"
  #
  AC_MSG_CHECKING([if signal can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([signal])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_signal="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_signal="no"
  ])
  #
  if test "$tst_links_signal" = "yes"; then
    AC_MSG_CHECKING([if signal is prototyped])
    AC_EGREP_CPP([signal],[
      $curl_includes_signal
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_signal="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_signal="no"
    ])
  fi
  #
  if test "$tst_proto_signal" = "yes"; then
    AC_MSG_CHECKING([if signal is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_signal
      ]],[[
        if(0 != signal(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_signal="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_signal="no"
    ])
  fi
  #
  if test "$tst_compi_signal" = "yes"; then
    AC_MSG_CHECKING([if signal usage allowed])
    if test "x$curl_disallow_signal" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_signal="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_signal="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if signal might be used])
  if test "$tst_links_signal" = "yes" &&
     test "$tst_proto_signal" = "yes" &&
     test "$tst_compi_signal" = "yes" &&
     test "$tst_allow_signal" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SIGNAL, 1,
      [Define to 1 if you have the signal function.])
    curl_cv_func_signal="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_signal="no"
  fi
])


dnl CURL_CHECK_FUNC_SIGSETJMP
dnl -------------------------------------------------
dnl Verify if sigsetjmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_sigsetjmp, then
dnl HAVE_SIGSETJMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SIGSETJMP], [
  AC_REQUIRE([CURL_INCLUDES_SETJMP])dnl
  #
  tst_links_sigsetjmp="unknown"
  tst_macro_sigsetjmp="unknown"
  tst_proto_sigsetjmp="unknown"
  tst_compi_sigsetjmp="unknown"
  tst_allow_sigsetjmp="unknown"
  #
  AC_MSG_CHECKING([if sigsetjmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([sigsetjmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_sigsetjmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_sigsetjmp="no"
  ])
  #
  if test "$tst_links_sigsetjmp" = "no"; then
    AC_MSG_CHECKING([if sigsetjmp seems a macro])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_setjmp
      ]],[[
        sigjmp_buf env;
        if(0 != sigsetjmp(env, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_macro_sigsetjmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_macro_sigsetjmp="no"
    ])
  fi
  #
  if test "$tst_links_sigsetjmp" = "yes"; then
    AC_MSG_CHECKING([if sigsetjmp is prototyped])
    AC_EGREP_CPP([sigsetjmp],[
      $curl_includes_setjmp
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_sigsetjmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_sigsetjmp="no"
    ])
  fi
  #
  if test "$tst_proto_sigsetjmp" = "yes" ||
     test "$tst_macro_sigsetjmp" = "yes"; then
    AC_MSG_CHECKING([if sigsetjmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_setjmp
      ]],[[
        sigjmp_buf env;
        if(0 != sigsetjmp(env, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_sigsetjmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_sigsetjmp="no"
    ])
  fi
  #
  if test "$tst_compi_sigsetjmp" = "yes"; then
    AC_MSG_CHECKING([if sigsetjmp usage allowed])
    if test "x$curl_disallow_sigsetjmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_sigsetjmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_sigsetjmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if sigsetjmp might be used])
  if (test "$tst_proto_sigsetjmp" = "yes" ||
      test "$tst_macro_sigsetjmp" = "yes") &&
     test "$tst_compi_sigsetjmp" = "yes" &&
     test "$tst_allow_sigsetjmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SIGSETJMP, 1,
      [Define to 1 if you have the sigsetjmp function or macro.])
    curl_cv_func_sigsetjmp="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_sigsetjmp="no"
  fi
])


dnl CURL_CHECK_FUNC_SOCKET
dnl -------------------------------------------------
dnl Verify if socket is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_socket, then
dnl HAVE_SOCKET will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SOCKET], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_INCLUDES_SOCKET])dnl
  #
  tst_links_socket="unknown"
  tst_proto_socket="unknown"
  tst_compi_socket="unknown"
  tst_allow_socket="unknown"
  #
  AC_MSG_CHECKING([if socket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_sys_socket
      $curl_includes_socket
    ]],[[
      if(0 != socket(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_socket="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_socket="no"
  ])
  #
  if test "$tst_links_socket" = "yes"; then
    AC_MSG_CHECKING([if socket is prototyped])
    AC_EGREP_CPP([socket],[
      $curl_includes_winsock2
      $curl_includes_sys_socket
      $curl_includes_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_socket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_socket="no"
    ])
  fi
  #
  if test "$tst_proto_socket" = "yes"; then
    AC_MSG_CHECKING([if socket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_sys_socket
        $curl_includes_socket
      ]],[[
        if(0 != socket(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_socket="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_socket="no"
    ])
  fi
  #
  if test "$tst_compi_socket" = "yes"; then
    AC_MSG_CHECKING([if socket usage allowed])
    if test "x$curl_disallow_socket" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_socket="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_socket="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if socket might be used])
  if test "$tst_links_socket" = "yes" &&
     test "$tst_proto_socket" = "yes" &&
     test "$tst_compi_socket" = "yes" &&
     test "$tst_allow_socket" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SOCKET, 1,
      [Define to 1 if you have the socket function.])
    curl_cv_func_socket="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_socket="no"
  fi
])


dnl CURL_CHECK_FUNC_SOCKETPAIR
dnl -------------------------------------------------
dnl Verify if socketpair is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_socketpair, then
dnl HAVE_SOCKETPAIR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_SOCKETPAIR], [
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_INCLUDES_SOCKET])dnl
  #
  tst_links_socketpair="unknown"
  tst_proto_socketpair="unknown"
  tst_compi_socketpair="unknown"
  tst_allow_socketpair="unknown"
  #
  AC_MSG_CHECKING([if socketpair can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([socketpair])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_socketpair="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_socketpair="no"
  ])
  #
  if test "$tst_links_socketpair" = "yes"; then
    AC_MSG_CHECKING([if socketpair is prototyped])
    AC_EGREP_CPP([socketpair],[
      $curl_includes_sys_socket
      $curl_includes_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_socketpair="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_socketpair="no"
    ])
  fi
  #
  if test "$tst_proto_socketpair" = "yes"; then
    AC_MSG_CHECKING([if socketpair is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_sys_socket
        $curl_includes_socket
      ]],[[
        int sv[2];
        if(0 != socketpair(0, 0, 0, sv))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_socketpair="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_socketpair="no"
    ])
  fi
  #
  if test "$tst_compi_socketpair" = "yes"; then
    AC_MSG_CHECKING([if socketpair usage allowed])
    if test "x$curl_disallow_socketpair" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_socketpair="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_socketpair="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if socketpair might be used])
  if test "$tst_links_socketpair" = "yes" &&
     test "$tst_proto_socketpair" = "yes" &&
     test "$tst_compi_socketpair" = "yes" &&
     test "$tst_allow_socketpair" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_SOCKETPAIR, 1,
      [Define to 1 if you have the socketpair function.])
    curl_cv_func_socketpair="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_socketpair="no"
  fi
])


dnl CURL_CHECK_FUNC_STRCASECMP
dnl -------------------------------------------------
dnl Verify if strcasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strcasecmp, then
dnl HAVE_STRCASECMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRCASECMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strcasecmp="unknown"
  tst_proto_strcasecmp="unknown"
  tst_compi_strcasecmp="unknown"
  tst_allow_strcasecmp="unknown"
  #
  AC_MSG_CHECKING([if strcasecmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strcasecmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strcasecmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strcasecmp="no"
  ])
  #
  if test "$tst_links_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp is prototyped])
    AC_EGREP_CPP([strcasecmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strcasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strcasecmp="no"
    ])
  fi
  #
  if test "$tst_proto_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strcasecmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strcasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strcasecmp="no"
    ])
  fi
  #
  if test "$tst_compi_strcasecmp" = "yes"; then
    AC_MSG_CHECKING([if strcasecmp usage allowed])
    if test "x$curl_disallow_strcasecmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strcasecmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strcasecmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strcasecmp might be used])
  if test "$tst_links_strcasecmp" = "yes" &&
     test "$tst_proto_strcasecmp" = "yes" &&
     test "$tst_compi_strcasecmp" = "yes" &&
     test "$tst_allow_strcasecmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRCASECMP, 1,
      [Define to 1 if you have the strcasecmp function.])
    curl_cv_func_strcasecmp="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strcasecmp="no"
  fi
])

dnl CURL_CHECK_FUNC_STRCMPI
dnl -------------------------------------------------
dnl Verify if strcmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strcmpi, then
dnl HAVE_STRCMPI will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRCMPI], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strcmpi="unknown"
  tst_proto_strcmpi="unknown"
  tst_compi_strcmpi="unknown"
  tst_allow_strcmpi="unknown"
  #
  AC_MSG_CHECKING([if strcmpi can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strcmpi])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strcmpi="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strcmpi="no"
  ])
  #
  if test "$tst_links_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi is prototyped])
    AC_EGREP_CPP([strcmpi],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strcmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strcmpi="no"
    ])
  fi
  #
  if test "$tst_proto_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strcmpi(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strcmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strcmpi="no"
    ])
  fi
  #
  if test "$tst_compi_strcmpi" = "yes"; then
    AC_MSG_CHECKING([if strcmpi usage allowed])
    if test "x$curl_disallow_strcmpi" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strcmpi="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strcmpi="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strcmpi might be used])
  if test "$tst_links_strcmpi" = "yes" &&
     test "$tst_proto_strcmpi" = "yes" &&
     test "$tst_compi_strcmpi" = "yes" &&
     test "$tst_allow_strcmpi" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRCMPI, 1,
      [Define to 1 if you have the strcmpi function.])
    curl_cv_func_strcmpi="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strcmpi="no"
  fi
])


dnl CURL_CHECK_FUNC_STRDUP
dnl -------------------------------------------------
dnl Verify if strdup is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strdup, then
dnl HAVE_STRDUP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRDUP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strdup="unknown"
  tst_proto_strdup="unknown"
  tst_compi_strdup="unknown"
  tst_allow_strdup="unknown"
  #
  AC_MSG_CHECKING([if strdup can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strdup])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strdup="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strdup="no"
  ])
  #
  if test "$tst_links_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup is prototyped])
    AC_EGREP_CPP([strdup],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strdup="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strdup="no"
    ])
  fi
  #
  if test "$tst_proto_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strdup(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strdup="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strdup="no"
    ])
  fi
  #
  if test "$tst_compi_strdup" = "yes"; then
    AC_MSG_CHECKING([if strdup usage allowed])
    if test "x$curl_disallow_strdup" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strdup="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strdup="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strdup might be used])
  if test "$tst_links_strdup" = "yes" &&
     test "$tst_proto_strdup" = "yes" &&
     test "$tst_compi_strdup" = "yes" &&
     test "$tst_allow_strdup" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRDUP, 1,
      [Define to 1 if you have the strdup function.])
    curl_cv_func_strdup="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strdup="no"
  fi
])


dnl CURL_CHECK_FUNC_STRERROR_R
dnl -------------------------------------------------
dnl Verify if strerror_r is available, prototyped, can be compiled and
dnl seems to work. If all of these are true, and usage has not been
dnl previously disallowed with shell variable curl_disallow_strerror_r,
dnl then HAVE_STRERROR_R and STRERROR_R_TYPE_ARG3 will be defined, as
dnl well as one of HAVE_GLIBC_STRERROR_R or HAVE_POSIX_STRERROR_R.
dnl
dnl glibc-style strerror_r:
dnl
dnl      char *strerror_r(int errnum, char *workbuf, size_t bufsize);
dnl
dnl  glibc-style strerror_r returns a pointer to the the error string,
dnl  and might use the provided workbuf as a scratch area if needed. A
dnl  quick test on a few systems shows that it's usually not used at all.
dnl
dnl POSIX-style strerror_r:
dnl
dnl      int strerror_r(int errnum, char *resultbuf, size_t bufsize);
dnl
dnl  POSIX-style strerror_r returns 0 upon successful completion and the
dnl  error string in the provided resultbuf.
dnl

AC_DEFUN([CURL_CHECK_FUNC_STRERROR_R], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strerror_r="unknown"
  tst_proto_strerror_r="unknown"
  tst_compi_strerror_r="unknown"
  tst_glibc_strerror_r="unknown"
  tst_posix_strerror_r="unknown"
  tst_allow_strerror_r="unknown"
  tst_works_glibc_strerror_r="unknown"
  tst_works_posix_strerror_r="unknown"
  tst_glibc_strerror_r_type_arg3="unknown"
  tst_posix_strerror_r_type_arg3="unknown"
  #
  AC_MSG_CHECKING([if strerror_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strerror_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strerror_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strerror_r="no"
  ])
  #
  if test "$tst_links_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is prototyped])
    AC_EGREP_CPP([strerror_r],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strerror_r="no"
    ])
  fi
  #
  if test "$tst_proto_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strerror_r(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strerror_r="no"
    ])
  fi
  #
  if test "$tst_compi_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r is glibc like])
    tst_glibc_strerror_r_type_arg3="unknown"
    for arg3 in 'size_t' 'int' 'unsigned int'; do
      if test "$tst_glibc_strerror_r_type_arg3" = "unknown"; then
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
            $curl_includes_string
            char *strerror_r(int errnum, char *workbuf, $arg3 bufsize);
          ]],[[
            if(0 != strerror_r(0, 0, 0))
              return 1;
          ]])
        ],[
          tst_glibc_strerror_r_type_arg3="$arg3"
        ])
      fi
    done
    case "$tst_glibc_strerror_r_type_arg3" in
      unknown)
        AC_MSG_RESULT([no])
        tst_glibc_strerror_r="no"
        ;;
      *)
        AC_MSG_RESULT([yes])
        tst_glibc_strerror_r="yes"
        ;;
    esac
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_glibc_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_string
#       include <errno.h>
      ]],[[
        char buffer[1024];
        char *string = 0;
        buffer[0] = '\0';
        string = strerror_r(EACCES, buffer, sizeof(buffer));
        if(!string)
          exit(1); /* fail */
        if(!string[0])
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_glibc_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_glibc_strerror_r="no"
    ])
  fi
  #
  if test "$tst_compi_strerror_r" = "yes" &&
    test "$tst_works_glibc_strerror_r" != "yes"; then
    AC_MSG_CHECKING([if strerror_r is POSIX like])
    tst_posix_strerror_r_type_arg3="unknown"
    for arg3 in 'size_t' 'int' 'unsigned int'; do
      if test "$tst_posix_strerror_r_type_arg3" = "unknown"; then
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
            $curl_includes_string
            int strerror_r(int errnum, char *resultbuf, $arg3 bufsize);
          ]],[[
            if(0 != strerror_r(0, 0, 0))
              return 1;
          ]])
        ],[
          tst_posix_strerror_r_type_arg3="$arg3"
        ])
      fi
    done
    case "$tst_posix_strerror_r_type_arg3" in
      unknown)
        AC_MSG_RESULT([no])
        tst_posix_strerror_r="no"
        ;;
      *)
        AC_MSG_RESULT([yes])
        tst_posix_strerror_r="yes"
        ;;
    esac
  fi
  #
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tst_posix_strerror_r" = "yes"; then
    AC_MSG_CHECKING([if strerror_r seems to work])
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_string
#       include <errno.h>
      ]],[[
        char buffer[1024];
        int error = 1;
        buffer[0] = '\0';
        error = strerror_r(EACCES, buffer, sizeof(buffer));
        if(error)
          exit(1); /* fail */
        if(buffer[0] == '\0')
          exit(1); /* fail */
        else
          exit(0);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_works_posix_strerror_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_works_posix_strerror_r="no"
    ])
  fi
  #
  if test "$tst_works_glibc_strerror_r" = "yes"; then
    tst_posix_strerror_r="no"
  fi
  if test "$tst_works_posix_strerror_r" = "yes"; then
    tst_glibc_strerror_r="no"
  fi
  if test "$tst_glibc_strerror_r" = "yes" &&
    test "$tst_works_glibc_strerror_r" != "no" &&
    test "$tst_posix_strerror_r" != "yes"; then
    tst_allow_strerror_r="check"
  fi
  if test "$tst_posix_strerror_r" = "yes" &&
    test "$tst_works_posix_strerror_r" != "no" &&
    test "$tst_glibc_strerror_r" != "yes"; then
    tst_allow_strerror_r="check"
  fi
  if test "$tst_allow_strerror_r" = "check"; then
    AC_MSG_CHECKING([if strerror_r usage allowed])
    if test "x$curl_disallow_strerror_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strerror_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strerror_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strerror_r might be used])
  if test "$tst_links_strerror_r" = "yes" &&
     test "$tst_proto_strerror_r" = "yes" &&
     test "$tst_compi_strerror_r" = "yes" &&
     test "$tst_allow_strerror_r" = "yes"; then
    AC_MSG_RESULT([yes])
    if test "$tst_glibc_strerror_r" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_STRERROR_R, 1,
        [Define to 1 if you have the strerror_r function.])
      AC_DEFINE_UNQUOTED(HAVE_GLIBC_STRERROR_R, 1,
        [Define to 1 if you have a working glibc-style strerror_r function.])
      AC_DEFINE_UNQUOTED(STRERROR_R_TYPE_ARG3, $tst_glibc_strerror_r_type_arg3,
        [Define to the type of arg 3 for strerror_r.])
    fi
    if test "$tst_posix_strerror_r" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_STRERROR_R, 1,
        [Define to 1 if you have the strerror_r function.])
      AC_DEFINE_UNQUOTED(HAVE_POSIX_STRERROR_R, 1,
        [Define to 1 if you have a working POSIX-style strerror_r function.])
      AC_DEFINE_UNQUOTED(STRERROR_R_TYPE_ARG3, $tst_posix_strerror_r_type_arg3,
        [Define to the type of arg 3 for strerror_r.])
    fi
    curl_cv_func_strerror_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strerror_r="no"
  fi
  #
  if test "$tst_compi_strerror_r" = "yes" &&
     test "$tst_allow_strerror_r" = "unknown"; then
    AC_MSG_WARN([cannot determine strerror_r() style: edit lib/curl_config.h manually.])
  fi
  #
])


dnl CURL_CHECK_FUNC_STRICMP
dnl -------------------------------------------------
dnl Verify if stricmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_stricmp, then
dnl HAVE_STRICMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRICMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_stricmp="unknown"
  tst_proto_stricmp="unknown"
  tst_compi_stricmp="unknown"
  tst_allow_stricmp="unknown"
  #
  AC_MSG_CHECKING([if stricmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([stricmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_stricmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_stricmp="no"
  ])
  #
  if test "$tst_links_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp is prototyped])
    AC_EGREP_CPP([stricmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_stricmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_stricmp="no"
    ])
  fi
  #
  if test "$tst_proto_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != stricmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_stricmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_stricmp="no"
    ])
  fi
  #
  if test "$tst_compi_stricmp" = "yes"; then
    AC_MSG_CHECKING([if stricmp usage allowed])
    if test "x$curl_disallow_stricmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_stricmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_stricmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if stricmp might be used])
  if test "$tst_links_stricmp" = "yes" &&
     test "$tst_proto_stricmp" = "yes" &&
     test "$tst_compi_stricmp" = "yes" &&
     test "$tst_allow_stricmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRICMP, 1,
      [Define to 1 if you have the stricmp function.])
    curl_cv_func_stricmp="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_stricmp="no"
  fi
])

dnl CURL_CHECK_FUNC_STRNCASECMP
dnl -------------------------------------------------
dnl Verify if strncasecmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strncasecmp, then
dnl HAVE_STRNCASECMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNCASECMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strncasecmp="unknown"
  tst_proto_strncasecmp="unknown"
  tst_compi_strncasecmp="unknown"
  tst_allow_strncasecmp="unknown"
  #
  AC_MSG_CHECKING([if strncasecmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strncasecmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strncasecmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strncasecmp="no"
  ])
  #
  if test "$tst_links_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp is prototyped])
    AC_EGREP_CPP([strncasecmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strncasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strncasecmp="no"
    ])
  fi
  #
  if test "$tst_proto_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strncasecmp(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strncasecmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strncasecmp="no"
    ])
  fi
  #
  if test "$tst_compi_strncasecmp" = "yes"; then
    AC_MSG_CHECKING([if strncasecmp usage allowed])
    if test "x$curl_disallow_strncasecmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strncasecmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strncasecmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strncasecmp might be used])
  if test "$tst_links_strncasecmp" = "yes" &&
     test "$tst_proto_strncasecmp" = "yes" &&
     test "$tst_compi_strncasecmp" = "yes" &&
     test "$tst_allow_strncasecmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNCASECMP, 1,
      [Define to 1 if you have the strncasecmp function.])
    curl_cv_func_strncasecmp="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strncasecmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRNCMPI
dnl -------------------------------------------------
dnl Verify if strncmpi is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strncmpi, then
dnl HAVE_STRNCMPI will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNCMPI], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strncmpi="unknown"
  tst_proto_strncmpi="unknown"
  tst_compi_strncmpi="unknown"
  tst_allow_strncmpi="unknown"
  #
  AC_MSG_CHECKING([if strncmpi can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strncmpi])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strncmpi="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strncmpi="no"
  ])
  #
  if test "$tst_links_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi is prototyped])
    AC_EGREP_CPP([strncmpi],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strncmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strncmpi="no"
    ])
  fi
  #
  if test "$tst_proto_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strncmpi(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strncmpi="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strncmpi="no"
    ])
  fi
  #
  if test "$tst_compi_strncmpi" = "yes"; then
    AC_MSG_CHECKING([if strncmpi usage allowed])
    if test "x$curl_disallow_strncmpi" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strncmpi="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strncmpi="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strncmpi might be used])
  if test "$tst_links_strncmpi" = "yes" &&
     test "$tst_proto_strncmpi" = "yes" &&
     test "$tst_compi_strncmpi" = "yes" &&
     test "$tst_allow_strncmpi" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNCMPI, 1,
      [Define to 1 if you have the strncmpi function.])
    curl_cv_func_strncmpi="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strncmpi="no"
  fi
])


dnl CURL_CHECK_FUNC_STRNICMP
dnl -------------------------------------------------
dnl Verify if strnicmp is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strnicmp, then
dnl HAVE_STRNICMP will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRNICMP], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strnicmp="unknown"
  tst_proto_strnicmp="unknown"
  tst_compi_strnicmp="unknown"
  tst_allow_strnicmp="unknown"
  #
  AC_MSG_CHECKING([if strnicmp can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strnicmp])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strnicmp="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strnicmp="no"
  ])
  #
  if test "$tst_links_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp is prototyped])
    AC_EGREP_CPP([strnicmp],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strnicmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strnicmp="no"
    ])
  fi
  #
  if test "$tst_proto_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strnicmp(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strnicmp="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strnicmp="no"
    ])
  fi
  #
  if test "$tst_compi_strnicmp" = "yes"; then
    AC_MSG_CHECKING([if strnicmp usage allowed])
    if test "x$curl_disallow_strnicmp" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strnicmp="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strnicmp="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strnicmp might be used])
  if test "$tst_links_strnicmp" = "yes" &&
     test "$tst_proto_strnicmp" = "yes" &&
     test "$tst_compi_strnicmp" = "yes" &&
     test "$tst_allow_strnicmp" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRNICMP, 1,
      [Define to 1 if you have the strnicmp function.])
    curl_cv_func_strnicmp="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strnicmp="no"
  fi
])


dnl CURL_CHECK_FUNC_STRSTR
dnl -------------------------------------------------
dnl Verify if strstr is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strstr, then
dnl HAVE_STRSTR will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRSTR], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strstr="unknown"
  tst_proto_strstr="unknown"
  tst_compi_strstr="unknown"
  tst_allow_strstr="unknown"
  #
  AC_MSG_CHECKING([if strstr can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strstr])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strstr="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strstr="no"
  ])
  #
  if test "$tst_links_strstr" = "yes"; then
    AC_MSG_CHECKING([if strstr is prototyped])
    AC_EGREP_CPP([strstr],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strstr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strstr="no"
    ])
  fi
  #
  if test "$tst_proto_strstr" = "yes"; then
    AC_MSG_CHECKING([if strstr is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strstr(0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strstr="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strstr="no"
    ])
  fi
  #
  if test "$tst_compi_strstr" = "yes"; then
    AC_MSG_CHECKING([if strstr usage allowed])
    if test "x$curl_disallow_strstr" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strstr="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strstr="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strstr might be used])
  if test "$tst_links_strstr" = "yes" &&
     test "$tst_proto_strstr" = "yes" &&
     test "$tst_compi_strstr" = "yes" &&
     test "$tst_allow_strstr" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRSTR, 1,
      [Define to 1 if you have the strstr function.])
    curl_cv_func_strstr="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strstr="no"
  fi
])


dnl CURL_CHECK_FUNC_STRTOK_R
dnl -------------------------------------------------
dnl Verify if strtok_r is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strtok_r, then
dnl HAVE_STRTOK_R will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRTOK_R], [
  AC_REQUIRE([CURL_INCLUDES_STRING])dnl
  #
  tst_links_strtok_r="unknown"
  tst_proto_strtok_r="unknown"
  tst_compi_strtok_r="unknown"
  tst_allow_strtok_r="unknown"
  #
  AC_MSG_CHECKING([if strtok_r can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtok_r])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strtok_r="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strtok_r="no"
  ])
  #
  if test "$tst_links_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r is prototyped])
    AC_EGREP_CPP([strtok_r],[
      $curl_includes_string
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strtok_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strtok_r="no"
    ])
  fi
  #
  if test "$tst_proto_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_string
      ]],[[
        if(0 != strtok_r(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strtok_r="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strtok_r="no"
    ])
  fi
  #
  if test "$tst_compi_strtok_r" = "yes"; then
    AC_MSG_CHECKING([if strtok_r usage allowed])
    if test "x$curl_disallow_strtok_r" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strtok_r="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strtok_r="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strtok_r might be used])
  if test "$tst_links_strtok_r" = "yes" &&
     test "$tst_proto_strtok_r" = "yes" &&
     test "$tst_compi_strtok_r" = "yes" &&
     test "$tst_allow_strtok_r" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRTOK_R, 1,
      [Define to 1 if you have the strtok_r function.])
    curl_cv_func_strtok_r="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strtok_r="no"
  fi
])


dnl CURL_CHECK_FUNC_STRTOLL
dnl -------------------------------------------------
dnl Verify if strtoll is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_strtoll, then
dnl HAVE_STRTOLL will be defined.

AC_DEFUN([CURL_CHECK_FUNC_STRTOLL], [
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
  #
  tst_links_strtoll="unknown"
  tst_proto_strtoll="unknown"
  tst_compi_strtoll="unknown"
  tst_allow_strtoll="unknown"
  #
  AC_MSG_CHECKING([if strtoll can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([strtoll])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_strtoll="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_strtoll="no"
  ])
  #
  if test "$tst_links_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll is prototyped])
    AC_EGREP_CPP([strtoll],[
      $curl_includes_stdlib
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_strtoll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_strtoll="no"
    ])
  fi
  #
  if test "$tst_proto_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
      ]],[[
        if(0 != strtoll(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_strtoll="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_strtoll="no"
    ])
  fi
  #
  if test "$tst_compi_strtoll" = "yes"; then
    AC_MSG_CHECKING([if strtoll usage allowed])
    if test "x$curl_disallow_strtoll" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_strtoll="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_strtoll="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if strtoll might be used])
  if test "$tst_links_strtoll" = "yes" &&
     test "$tst_proto_strtoll" = "yes" &&
     test "$tst_compi_strtoll" = "yes" &&
     test "$tst_allow_strtoll" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_STRTOLL, 1,
      [Define to 1 if you have the strtoll function.])
    curl_cv_func_strtoll="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_strtoll="no"
  fi
])


dnl CURL_CHECK_FUNC_WRITEV
dnl -------------------------------------------------
dnl Verify if writev is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_writev, then
dnl HAVE_WRITEV will be defined.

AC_DEFUN([CURL_CHECK_FUNC_WRITEV], [
  AC_REQUIRE([CURL_INCLUDES_SYS_UIO])dnl
  #
  tst_links_writev="unknown"
  tst_proto_writev="unknown"
  tst_compi_writev="unknown"
  tst_allow_writev="unknown"
  #
  AC_MSG_CHECKING([if writev can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([writev])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_writev="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_writev="no"
  ])
  #
  if test "$tst_links_writev" = "yes"; then
    AC_MSG_CHECKING([if writev is prototyped])
    AC_EGREP_CPP([writev],[
      $curl_includes_sys_uio
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_writev="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_writev="no"
    ])
  fi
  #
  if test "$tst_proto_writev" = "yes"; then
    AC_MSG_CHECKING([if writev is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_sys_uio
      ]],[[
        if(0 != writev(0, 0, 0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_writev="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_writev="no"
    ])
  fi
  #
  if test "$tst_compi_writev" = "yes"; then
    AC_MSG_CHECKING([if writev usage allowed])
    if test "x$curl_disallow_writev" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_writev="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_writev="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if writev might be used])
  if test "$tst_links_writev" = "yes" &&
     test "$tst_proto_writev" = "yes" &&
     test "$tst_compi_writev" = "yes" &&
     test "$tst_allow_writev" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_WRITEV, 1,
      [Define to 1 if you have the writev function.])
    curl_cv_func_writev="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_writev="no"
  fi
])
