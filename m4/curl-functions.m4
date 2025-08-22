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
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h netinet/in.h arpa/inet.h,
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
#ifndef _WIN32
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
    sys/types.h netinet/in.h ifaddrs.h,
    [], [], [$curl_includes_ifaddrs])
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
#include <setjmp.h>
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
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
#include <signal.h>
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
    [], [], [$curl_includes_signal])
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
#include <stdlib.h>
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
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
#include <string.h>
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h strings.h,
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
#ifndef _WIN32
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
    sys/types.h unistd.h sys/ioctl.h stropts.h,
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
#ifndef _WIN32
#  include <sys/socket.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
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
curl_includes_time="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if !defined(_WIN32) || defined(__MINGW32__)
#  include <sys/time.h>
#endif
#include <time.h>
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h,
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
dnl included when winsock2.h is to be included.

AC_DEFUN([CURL_INCLUDES_WINSOCK2], [
curl_includes_winsock2="\
/* includes start */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#endif
/* includes end */"
  CURL_CHECK_NATIVE_WINDOWS
])


dnl CURL_INCLUDES_WS2TCPIP
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when ws2tcpip.h is to be included.

AC_DEFUN([CURL_INCLUDES_WS2TCPIP], [
curl_includes_ws2tcpip="\
/* includes start */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
/* includes end */"
  CURL_CHECK_NATIVE_WINDOWS
])


dnl CURL_INCLUDES_BSDSOCKET
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when bsdsocket.h is to be included.

AC_DEFUN([CURL_INCLUDES_BSDSOCKET], [
curl_includes_bsdsocket="\
/* includes start */
#ifdef HAVE_PROTO_BSDSOCKET_H
#  define __NO_NET_API
#  define __USE_INLINE__
#  include <proto/bsdsocket.h>
#  ifdef HAVE_SYS_IOCTL_H
#    include <sys/ioctl.h>
#  endif
#  ifdef __amigaos4__
struct SocketIFace *ISocket = NULL;
#  else
struct Library *SocketBase = NULL;
#  endif
#  define select(a,b,c,d,e) WaitSelect(a,b,c,d,e,0)
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    proto/bsdsocket.h,
    [], [], [$curl_includes_bsdsocket])
])

dnl CURL_INCLUDES_NETIF
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when net/if.h is to be included.

AC_DEFUN([CURL_INCLUDES_NETIF], [
curl_includes_netif="\
/* includes start */
#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    net/if.h,
    [], [], [$curl_includes_netif])
])


dnl CURL_PREPROCESS_CALLCONV
dnl -------------------------------------------------
dnl Set up variable with a preprocessor block which
dnl defines function calling convention.

AC_DEFUN([CURL_PREPROCESS_CALLCONV], [
curl_preprocess_callconv="\
/* preprocess start */
#ifdef _WIN32
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
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  #
  tst_links_closesocket_camel="unknown"
  tst_compi_closesocket_camel="unknown"
  tst_allow_closesocket_camel="unknown"
  #
  AC_MSG_CHECKING([if CloseSocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_bsdsocket
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
    AC_MSG_CHECKING([if CloseSocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_bsdsocket
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
    sunos4* | aix3*)
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
          if(0 != fsetxattr(0, "", 0, 0, 0))
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
      struct addrinfo *ai = 0;
      if(0 != getaddrinfo(0, 0, 0, &ai))
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
        struct addrinfo *ai = 0;
        if(0 != getaddrinfo(0, 0, 0, &ai))
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
    CURL_RUN_IFELSE([
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
        int exitcode;

        #ifdef _WIN32
        WSADATA wsa;
        if(WSAStartup(MAKEWORD(2, 2), &wsa))
          return 2;
        #endif

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo("127.0.0.1", 0, &hints, &ai);
        if(error || !ai)
          exitcode = 1; /* fail */
        else {
          freeaddrinfo(ai);
          exitcode = 0;
        }
        #ifdef _WIN32
        WSACleanup();
        #endif
        return exitcode;
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
  if test "$tst_proto_getaddrinfo" = "yes" &&
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
    if test "$curl_cv_apple" = 'yes'; then
      dnl Darwin 6.0 and macOS 10.2.X and newer
      tst_tsafe_getaddrinfo="yes"
    fi
    case $host_os in
      aix[[1234]].* | aix5.[[01]].*)
        dnl AIX 5.1 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      aix*)
        dnl AIX 5.2 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      darwin[[12345]].*)
        dnl Darwin 5.0 and macOS 10.1.X and older
        tst_tsafe_getaddrinfo="no"
        ;;
      freebsd[[1234]].* | freebsd5.[[1234]]*)
        dnl FreeBSD 5.4 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      freebsd*)
        dnl FreeBSD 5.5 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      hpux[[123456789]].* | hpux10.* | hpux11.0* | hpux11.10*)
        dnl HP-UX 11.10 and older
        tst_tsafe_getaddrinfo="no"
        ;;
      hpux*)
        dnl HP-UX 11.11 and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      midnightbsd*)
        dnl all MidnightBSD versions
        tst_tsafe_getaddrinfo="yes"
        ;;
      netbsd[[123]].*)
        dnl NetBSD 3.X and older
        tst_tsafe_getaddrinfo="no"
        ;;
      netbsd*)
        dnl NetBSD 4.X and newer
        tst_tsafe_getaddrinfo="yes"
        ;;
      *bsd*)
        dnl All other BSD's
        tst_tsafe_getaddrinfo="no"
        ;;
      solaris2*)
        dnl Solaris which have it
        tst_tsafe_getaddrinfo="yes"
        ;;
    esac
    if test "$tst_tsafe_getaddrinfo" = "unknown" &&
       test "$curl_cv_native_windows" = "yes"; then
      tst_tsafe_getaddrinfo="yes"
    fi
    if test "$tst_tsafe_getaddrinfo" = "unknown"; then
      tst_tsafe_getaddrinfo="yes"
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
          $curl_includes_bsdsocket
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
          $curl_includes_bsdsocket
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
          $curl_includes_bsdsocket
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
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
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
      $curl_includes_bsdsocket
    ]],[[
      char s[1];
      if(0 != gethostname((void *)s, 0))
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
      $curl_includes_bsdsocket
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
        $curl_includes_bsdsocket
      ]],[[
        char s[1];
        if(0 != gethostname((void *)s, 0))
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
              $curl_includes_bsdsocket
              $curl_preprocess_callconv
              #if defined(_WIN32) && defined(WINSOCK_API_LINKAGE)
              WINSOCK_API_LINKAGE
              #else
              extern
              #endif
              int FUNCALLCONV gethostname($tst_arg1, $tst_arg2);
            ]],[[
              char s[1];
              if(0 != gethostname(($tst_arg1)s, 0))
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

dnl CURL_CHECK_FUNC_GETPEERNAME
dnl -------------------------------------------------
dnl Verify if getpeername is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_getpeername, then
dnl HAVE_GETPEERNAME will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETPEERNAME], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  AC_REQUIRE([CURL_PREPROCESS_CALLCONV])dnl
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  #
  tst_links_getpeername="unknown"
  tst_proto_getpeername="unknown"
  tst_compi_getpeername="unknown"
  tst_allow_getpeername="unknown"
  #
  AC_MSG_CHECKING([if getpeername can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
    ]],[[
      if(0 != getpeername(0, (void *)0, (void *)0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getpeername="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getpeername="no"
  ])
  #
  if test "$tst_links_getpeername" = "yes"; then
    AC_MSG_CHECKING([if getpeername is prototyped])
    AC_EGREP_CPP([getpeername],[
      $curl_includes_winsock2
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getpeername="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getpeername="no"
    ])
  fi
  #
  if test "$tst_proto_getpeername" = "yes"; then
    AC_MSG_CHECKING([if getpeername is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_bsdsocket
        $curl_includes_sys_socket
      ]],[[
        if(0 != getpeername(0, (void *)0, (void *)0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_getpeername="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_getpeername="no"
    ])
  fi
  #
  if test "$tst_compi_getpeername" = "yes"; then
    AC_MSG_CHECKING([if getpeername usage allowed])
    if test "x$curl_disallow_getpeername" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getpeername="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getpeername="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getpeername might be used])
  if test "$tst_links_getpeername" = "yes" &&
     test "$tst_proto_getpeername" = "yes" &&
     test "$tst_compi_getpeername" = "yes" &&
     test "$tst_allow_getpeername" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETPEERNAME, 1,
      [Define to 1 if you have the getpeername function.])
    curl_cv_func_getpeername="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getpeername="no"
  fi
])

dnl CURL_CHECK_FUNC_GETSOCKNAME
dnl -------------------------------------------------
dnl Verify if getsockname is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable curl_disallow_getsockname, then
dnl HAVE_GETSOCKNAME will be defined.

AC_DEFUN([CURL_CHECK_FUNC_GETSOCKNAME], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_REQUIRE([CURL_INCLUDES_UNISTD])dnl
  AC_REQUIRE([CURL_PREPROCESS_CALLCONV])dnl
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  #
  tst_links_getsockname="unknown"
  tst_proto_getsockname="unknown"
  tst_compi_getsockname="unknown"
  tst_allow_getsockname="unknown"
  #
  AC_MSG_CHECKING([if getsockname can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_winsock2
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
    ]],[[
      if(0 != getsockname(0, (void *)0, (void *)0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_getsockname="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_getsockname="no"
  ])
  #
  if test "$tst_links_getsockname" = "yes"; then
    AC_MSG_CHECKING([if getsockname is prototyped])
    AC_EGREP_CPP([getsockname],[
      $curl_includes_winsock2
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
    ],[
      AC_MSG_RESULT([yes])
      tst_proto_getsockname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_proto_getsockname="no"
    ])
  fi
  #
  if test "$tst_proto_getsockname" = "yes"; then
    AC_MSG_CHECKING([if getsockname is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_winsock2
        $curl_includes_bsdsocket
        $curl_includes_sys_socket
      ]],[[
        if(0 != getsockname(0, (void *)0, (void *)0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_compi_getsockname="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_compi_getsockname="no"
    ])
  fi
  #
  if test "$tst_compi_getsockname" = "yes"; then
    AC_MSG_CHECKING([if getsockname usage allowed])
    if test "x$curl_disallow_getsockname" != "xyes"; then
      AC_MSG_RESULT([yes])
      tst_allow_getsockname="yes"
    else
      AC_MSG_RESULT([no])
      tst_allow_getsockname="no"
    fi
  fi
  #
  AC_MSG_CHECKING([if getsockname might be used])
  if test "$tst_links_getsockname" = "yes" &&
     test "$tst_proto_getsockname" = "yes" &&
     test "$tst_compi_getsockname" = "yes" &&
     test "$tst_allow_getsockname" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_GETSOCKNAME, 1,
      [Define to 1 if you have the getsockname function.])
    curl_cv_func_getsockname="yes"
  else
    AC_MSG_RESULT([no])
    curl_cv_func_getsockname="no"
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
    CURL_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_ifaddrs
      ]],[[
        struct ifaddrs *ifa = 0;
        int error;

        error = getifaddrs(&ifa);
        if(error || !ifa)
          return 1; /* fail */
        else {
          freeifaddrs(ifa);
          return 0;
        }
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
        time_t tm = 1170352587;
        struct tm result;
        if(0 != gmtime_r(&tm, &result))
          return 1;
        (void)result;
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
    CURL_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_time
      ]],[[
        time_t local = 1170352587;
        struct tm *gmt = 0;
        struct tm result;
        gmt = gmtime_r(&local, &result);
        (void)result;
        if(gmt)
          return 0;
        else
          return 1;
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
        char ipv4res[sizeof("255.255.255.255")];
        unsigned char ipv4a[5] = "";
        if(0 != inet_ntop(0, ipv4a, ipv4res, 0))
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
    CURL_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_arpa_inet
        $curl_includes_string
      ]],[[
        char ipv6res[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
        char ipv4res[sizeof("255.255.255.255")];
        unsigned char ipv6a[26];
        unsigned char ipv4a[5];
        const char *ipv6ptr = 0;
        const char *ipv4ptr = 0;
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
          return 1; /* fail */
        if(ipv4ptr != ipv4res)
          return 1; /* fail */
        if(!ipv4ptr[0])
          return 1; /* fail */
        if(memcmp(ipv4res, "192.168.100.1", 13) != 0)
          return 1; /* fail */
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
          return 1; /* fail */
        if(ipv6ptr != ipv6res)
          return 1; /* fail */
        if(!ipv6ptr[0])
          return 1; /* fail */
        if(memcmp(ipv6res, "fe80::214:4fff:fe0b:76c8", 24) != 0)
          return 1; /* fail */
        /* - */
        return 0;
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
      [Define to 1 if you have an IPv6 capable working inet_ntop function.])
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
        unsigned char ipv4a[4+1] = "";
        const char *ipv4src = "192.168.100.1";
        if(0 != inet_pton(0, ipv4src, ipv4a))
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
    CURL_RUN_IFELSE([
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
          return 1; /* fail */
        /* - */
        if( (ipv4a[0] != 0xc0) ||
            (ipv4a[1] != 0xa8) ||
            (ipv4a[2] != 0x64) ||
            (ipv4a[3] != 0x01) ||
            (ipv4a[4] != 0x01) )
          return 1; /* fail */
        /* - */
        memset(ipv6a, 1, sizeof(ipv6a));
        if(1 != inet_pton(AF_INET6, ipv6src, ipv6a))
          return 1; /* fail */
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
          return 1; /* fail */
        /* - */
        if( (ipv6a[2]  != 0x0) ||
            (ipv6a[3]  != 0x0) ||
            (ipv6a[4]  != 0x0) ||
            (ipv6a[5]  != 0x0) ||
            (ipv6a[6]  != 0x0) ||
            (ipv6a[7]  != 0x0) )
          return 1; /* fail */
        /* - */
        return 0;
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
      [Define to 1 if you have an IPv6 capable working inet_pton function.])
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
dnl curl_cv_func_ioctl is set to "yes".

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
        unsigned long flags = 0;
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
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  #
  tst_links_ioctlsocket_camel="unknown"
  tst_compi_ioctlsocket_camel="unknown"
  tst_allow_ioctlsocket_camel="unknown"
  #
  AC_MSG_CHECKING([if IoctlSocket can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_bsdsocket
    ]],[[
      if(0 != IoctlSocket(0, 0, 0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_ioctlsocket_camel="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_ioctlsocket_camel="no"
  ])
  #
  if test "$tst_links_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_bsdsocket
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
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  #
  tst_compi_ioctlsocket_camel_fionbio="unknown"
  tst_allow_ioctlsocket_camel_fionbio="unknown"
  #
  if test "$curl_cv_func_ioctlsocket_camel" = "yes"; then
    AC_MSG_CHECKING([if IoctlSocket FIONBIO is compilable])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_bsdsocket
      ]],[[
        long flags = 0;
        if(0 != IoctlSocket(0, FIONBIO, &flags))
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
        if(0 != memrchr("", 0, 0))
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
        if(0 != memrchr("", 0, 0))
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
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
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
      $curl_includes_bsdsocket
      $curl_includes_sys_socket
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
        $curl_includes_bsdsocket
        $curl_includes_sys_socket
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
        if(0 != strcasecmp("", ""))
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
  AC_REQUIRE([CURL_INCLUDES_STDLIB])dnl
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
        $curl_includes_stdlib
      ]],[[
        free(strdup(""));
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
dnl then HAVE_STRERROR_R will be defined, as well as one of
dnl HAVE_GLIBC_STRERROR_R or HAVE_POSIX_STRERROR_R.
dnl
dnl glibc-style strerror_r:
dnl
dnl      char *strerror_r(int errnum, char *workbuf, size_t bufsize);
dnl
dnl  glibc-style strerror_r returns a pointer to the error string,
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
        char s[1];
        if(0 != strerror_r(0, s, 0))
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
            char s[1];
            if(0 != strerror_r(0, s, 0))
              return 1;
            (void)s;
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
    CURL_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_string
        #include <errno.h>
      ]],[[
        char buffer[1024];
        char *string = 0;
        buffer[0] = '\0';
        string = strerror_r(EACCES, buffer, sizeof(buffer));
        if(!string)
          return 1; /* fail */
        if(!string[0])
          return 1; /* fail */
        else
          return 0;
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
            char s[1];
            if(0 != strerror_r(0, s, 0))
              return 1;
            (void)s;
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
    CURL_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_stdlib
        $curl_includes_string
        #include <errno.h>
      ]],[[
        char buffer[1024];
        int error = 1;
        buffer[0] = '\0';
        error = strerror_r(EACCES, buffer, sizeof(buffer));
        if(error)
          return 1; /* fail */
        if(buffer[0] == '\0')
          return 1; /* fail */
        else
          return 0;
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
    fi
    if test "$tst_posix_strerror_r" = "yes"; then
      AC_DEFINE_UNQUOTED(HAVE_STRERROR_R, 1,
        [Define to 1 if you have the strerror_r function.])
      AC_DEFINE_UNQUOTED(HAVE_POSIX_STRERROR_R, 1,
        [Define to 1 if you have a working POSIX-style strerror_r function.])
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

dnl CURL_RUN_IFELSE
dnl -------------------------------------------------
dnl Wrapper macro to use instead of AC_RUN_IFELSE. It
dnl sets LD_LIBRARY_PATH locally for this run only, from the
dnl CURL_LIBRARY_PATH variable. It keeps the LD_LIBRARY_PATH
dnl changes contained within this macro.

AC_DEFUN([CURL_RUN_IFELSE], [
  if test "$curl_cv_apple" = 'yes'; then
    AC_RUN_IFELSE([AC_LANG_SOURCE([$1])], $2, $3, $4)
  else
    oldcc=$CC
    old=$LD_LIBRARY_PATH
    CC="sh ./run-compiler"
    LD_LIBRARY_PATH=$CURL_LIBRARY_PATH:$old
    export LD_LIBRARY_PATH
    AC_RUN_IFELSE([AC_LANG_SOURCE([$1])], $2, $3, $4)
    LD_LIBRARY_PATH=$old # restore
    CC=$oldcc
  fi
])

dnl CURL_COVERAGE
dnl --------------------------------------------------
dnl Switch on options and libs to build with gcc's code coverage.
dnl

AC_DEFUN([CURL_COVERAGE],[
  AC_REQUIRE([AC_PROG_SED])
  AC_REQUIRE([AC_ARG_ENABLE])
  AC_MSG_CHECKING([for code coverage support])
  coverage="no"
  curl_coverage_msg="disabled"

  dnl check if enabled by argument
  AC_ARG_ENABLE(code-coverage,
    AS_HELP_STRING([--enable-code-coverage], [Provide code coverage]),
    coverage="$enableval")

  dnl if not gcc switch off again
  AS_IF([ test "$GCC" != "yes" ], coverage="no" )
  AC_MSG_RESULT($coverage)

  if test "x$coverage" = "xyes"; then
    curl_coverage_msg="enabled"

    AC_CHECK_TOOL([GCOV], [gcov], [gcov])
    if test -z "$GCOV"; then
      AC_MSG_ERROR([needs gcov for code coverage])
    fi
    AC_CHECK_PROG([LCOV], [lcov], [lcov])
    if test -z "$LCOV"; then
      AC_MSG_ERROR([needs lcov for code coverage])
    fi

    CPPFLAGS="$CPPFLAGS -DNDEBUG"
    CFLAGS="$CFLAGS -O0 -g -fprofile-arcs -ftest-coverage"
    LIBS="$LIBS -lgcov"
  fi
])

dnl CURL_ATOMIC
dnl -------------------------------------------------------------
dnl Check if _Atomic works. But only check if stdatomic.h exists.
dnl
AC_DEFUN([CURL_ATOMIC],[
  AC_CHECK_HEADERS(stdatomic.h, [
    AC_MSG_CHECKING([if _Atomic is available])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        $curl_includes_unistd
      ]],[[
        _Atomic int i = 0;
        i = 4;  // Force an atomic-write operation.
        (void)i;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED(HAVE_ATOMIC, 1,
        [Define to 1 if you have _Atomic support.])
      tst_atomic="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_atomic="no"
    ])
  ])
])

# Rewrite inspired by the functionality once provided by
# AX_COMPILE_CHECK_SIZEOF. Uses the switch() "trick" to find the size of the
# given type.
#
# This code fails to compile:
#
#   switch() { case 0: case 0: }
#
# By making the second case number a boolean check, it fails to compile the
# test code when the boolean is false and thus creating a zero, making it a
# duplicated case label. If the boolean equals true, it becomes a one, the
# code compiles and we know it was a match.
#
# The check iterates over all possible sizes and stops as soon it compiles
# error-free.
#
# Usage:
#
#   CURL_SIZEOF(TYPE, [HEADERS])
#

AC_DEFUN([CURL_SIZEOF], [
  dnl The #define name to make autoheader put the name in curl_config.h.in
  define(TYPE, translit(sizeof_$1, [a-z *], [A-Z_P]))dnl

  AC_MSG_CHECKING(size of $1)
  r=0
  dnl Check the sizes in a reasonable order
  for typesize in 8 4 2 16 1; do
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #include <sys/types.h>
        $2
      ]],[
        switch(0) {
          case 0:
          case (sizeof($1) == $typesize):;
        }
      ])
    ],[
      r=$typesize
    ],[
      r=0
    ])
    dnl get out of the loop once matched
    if test $r -gt 0; then
      break;
    fi
  done
  if test $r -eq 0; then
    AC_MSG_ERROR([Failed to find size of $1])
  fi
  AC_MSG_RESULT($r)
  dnl lowercase and underscore instead of space
  tname=`echo "ac_cv_sizeof_$1" | tr A-Z a-z | tr " " "_"`
  eval "$tname=$r"

  AC_DEFINE_UNQUOTED(TYPE, [$r], [Size of $1 in number of bytes])

])
