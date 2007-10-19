#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################


dnl CURL_CHECK_HEADER_WINDOWS
dnl -------------------------------------------------
dnl Check for compilable and valid windows.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINDOWS], [
  AC_CACHE_CHECK([for windows.h], [ac_cv_header_windows_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WINDOWS_H shall not be defined.
#else
        int dummy=2*WINVER;
#endif
      ])
    ],[
      ac_cv_header_windows_h="yes"
    ],[
      ac_cv_header_windows_h="no"
    ])
  ])
  case "$ac_cv_header_windows_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINDOWS_H, 1,
        [Define to 1 if you have the windows.h header file.])
      AC_DEFINE_UNQUOTED(WIN32_LEAN_AND_MEAN, 1,
        [Define to avoid automatic inclusion of winsock.h])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_WINSOCK
dnl -------------------------------------------------
dnl Check for compilable and valid winsock.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock.h], [ac_cv_header_winsock_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WINSOCK_H shall not be defined.
#else
        int dummy=WSACleanup();
#endif
      ])
    ],[
      ac_cv_header_winsock_h="yes"
    ],[
      ac_cv_header_winsock_h="no"
    ])
  ])
  case "$ac_cv_header_winsock_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINSOCK_H, 1,
        [Define to 1 if you have the winsock.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_WINSOCK2
dnl -------------------------------------------------
dnl Check for compilable and valid winsock2.h header 

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK2], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock2.h], [ac_cv_header_winsock2_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WINSOCK2_H shall not be defined.
#else
        int dummy=2*IPPROTO_ESP;
#endif
      ])
    ],[
      ac_cv_header_winsock2_h="yes"
    ],[
      ac_cv_header_winsock2_h="no"
    ])
  ])
  case "$ac_cv_header_winsock2_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINSOCK2_H, 1,
        [Define to 1 if you have the winsock2.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_WS2TCPIP
dnl -------------------------------------------------
dnl Check for compilable and valid ws2tcpip.h header

AC_DEFUN([CURL_CHECK_HEADER_WS2TCPIP], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CACHE_CHECK([for ws2tcpip.h], [ac_cv_header_ws2tcpip_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WS2TCPIP_H shall not be defined.
#else
        int dummy=2*IP_PKTINFO;
#endif
      ])
    ],[
      ac_cv_header_ws2tcpip_h="yes"
    ],[
      ac_cv_header_ws2tcpip_h="no"
    ])
  ])
  case "$ac_cv_header_ws2tcpip_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WS2TCPIP_H, 1,
        [Define to 1 if you have the ws2tcpip.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_WINLDAP
dnl -------------------------------------------------
dnl Check for compilable and valid winldap.h header

AC_DEFUN([CURL_CHECK_HEADER_WINLDAP], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winldap.h], [ac_cv_header_winldap_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <winldap.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WINLDAP_H shall not be defined.
#else
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        ULONG res = ldap_unbind(ldp);
#endif
      ])
    ],[
      ac_cv_header_winldap_h="yes"
    ],[
      ac_cv_header_winldap_h="no"
    ])
  ])
  case "$ac_cv_header_winldap_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINLDAP_H, 1,
        [Define to 1 if you have the winldap.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_WINBER
dnl -------------------------------------------------
dnl Check for compilable and valid winber.h header

AC_DEFUN([CURL_CHECK_HEADER_WINBER], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINLDAP])dnl
  AC_CACHE_CHECK([for winber.h], [ac_cv_header_winber_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <winldap.h>
#include <winber.h>
      ],[
#ifdef __CYGWIN__
        HAVE_WINBER_H shall not be defined.
#else
        BERVAL *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
#endif
      ])
    ],[
      ac_cv_header_winber_h="yes"
    ],[
      ac_cv_header_winber_h="no"
    ])
  ])
  case "$ac_cv_header_winber_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINBER_H, 1,
        [Define to 1 if you have the winber.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_LBER
dnl -------------------------------------------------
dnl Check for compilable and valid lber.h header,
dnl and check if it is needed even with ldap.h

AC_DEFUN([CURL_CHECK_HEADER_LBER], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for lber.h], [ac_cv_header_lber_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef NULL
#define NULL (void *)0
#endif
#include <lber.h>
      ],[
        BerValue *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
      ])
    ],[
      ac_cv_header_lber_h="yes"
    ],[
      ac_cv_header_lber_h="no"
    ])
  ])
  if test "$ac_cv_header_lber_h" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_LBER_H, 1,
      [Define to 1 if you have the lber.h header file.])
    #
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef NULL
#define NULL (void *)0
#endif
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#include <ldap.h>
      ],[
        BerValue *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
      ])
    ],[
      curl_cv_need_header_lber_h="no"
    ],[
      curl_cv_need_header_lber_h="yes"
    ])
    #
    case "$curl_cv_need_header_lber_h" in
      yes)
        AC_DEFINE_UNQUOTED(NEED_LBER_H, 1,
          [Define to 1 if you need the lber.h header file even with ldap.h])
        ;;
    esac
  fi
])


dnl CURL_CHECK_HEADER_LDAP
dnl -------------------------------------------------
dnl Check for compilable and valid ldap.h header

AC_DEFUN([CURL_CHECK_HEADER_LDAP], [
  AC_REQUIRE([CURL_CHECK_HEADER_LBER])dnl
  AC_CACHE_CHECK([for ldap.h], [ac_cv_header_ldap_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#ifdef NEED_LBER_H
#include <lber.h>
#endif
#include <ldap.h>
      ],[
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        int res = ldap_unbind(ldp);
      ])
    ],[
      ac_cv_header_ldap_h="yes"
    ],[
      ac_cv_header_ldap_h="no"
    ])
  ])
  case "$ac_cv_header_ldap_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_LDAP_H, 1,
        [Define to 1 if you have the ldap.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_LDAP_SSL
dnl -------------------------------------------------
dnl Check for compilable and valid ldap_ssl.h header

AC_DEFUN([CURL_CHECK_HEADER_LDAP_SSL], [
  AC_REQUIRE([CURL_CHECK_HEADER_LDAP])dnl
  AC_CACHE_CHECK([for ldap_ssl.h], [ac_cv_header_ldap_ssl_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#ifdef NEED_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#include <ldap_ssl.h>
      ],[
        LDAP *ldp = ldapssl_init("dummy", LDAPS_PORT, 1);
      ])
    ],[
      ac_cv_header_ldap_ssl_h="yes"
    ],[
      ac_cv_header_ldap_ssl_h="no"
    ])
  ])
  case "$ac_cv_header_ldap_ssl_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_LDAP_SSL_H, 1,
        [Define to 1 if you have the ldap_ssl.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_HEADER_LDAPSSL
dnl -------------------------------------------------
dnl Check for compilable and valid ldapssl.h header

AC_DEFUN([CURL_CHECK_HEADER_LDAPSSL], [
  AC_REQUIRE([CURL_CHECK_HEADER_LDAP])dnl
  AC_CACHE_CHECK([for ldapssl.h], [ac_cv_header_ldapssl_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef NULL
#define NULL (void *)0
#endif
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#ifdef NEED_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#include <ldapssl.h>
      ],[
        char *cert_label = NULL;
        LDAP *ldp = ldap_ssl_init("dummy", LDAPS_PORT, cert_label);
      ])
    ],[
      ac_cv_header_ldapssl_h="yes"
    ],[
      ac_cv_header_ldapssl_h="no"
    ])
  ])
  case "$ac_cv_header_ldapssl_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_LDAPSSL_H, 1,
        [Define to 1 if you have the ldapssl.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_LIBS_WINLDAP
dnl -------------------------------------------------
dnl Check for libraries needed for WINLDAP support,
dnl and prepended to LIBS any needed libraries.
dnl This macro can take an optional parameter with a
dnl white space separated list of libraries to check
dnl before the WINLDAP default ones.

AC_DEFUN([CURL_CHECK_LIBS_WINLDAP], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINBER])dnl
  #
  AC_MSG_CHECKING([for WINLDAP libraries])
  #
  u_libs=""
  #
  ifelse($1,,,[
    for x_lib in $1; do
      case "$x_lib" in
        -l*)
          l_lib="$x_lib"
          ;;
        *)
          l_lib="-l$x_lib"
          ;;
      esac
      if test -z "$u_libs"; then
        u_libs="$l_lib"
      else
        u_libs="$u_libs $l_lib"
      fi
    done
  ])
  #
  curl_cv_save_LIBS=$LIBS
  curl_cv_ldap_LIBS="unknown"
  #
  for x_nlibs in '' "$u_libs" \
    '-lwldap32' ; do
    if test -z "$x_nlibs"; then
      LIBS="$curl_cv_save_LIBS"
    else
      LIBS="$x_nlibs $curl_cv_save_LIBS"
    fi
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINLDAP_H
#include <winldap.h>
#endif
#ifdef HAVE_WINBER_H
#include <winber.h>
#endif
#endif
      ],[
        BERVAL *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        ULONG res = ldap_unbind(ldp);
        ber_free(bep, 1);
      ])
    ],[
       curl_cv_ldap_LIBS="$x_nlibs"
       break
    ])
  done
  #
  LIBS=$curl_cv_save_LIBS
  #
  case X-"$curl_cv_ldap_LIBS" in
    X-unknown)
      AC_MSG_RESULT([cannot find WINLDAP libraries])
      ;;
    X-)
      AC_MSG_RESULT([no additional lib required])
      ;;
    *)
      if test -z "$curl_cv_save_LIBS"; then
        LIBS="$curl_cv_ldap_LIBS"
      else
        LIBS="$curl_cv_ldap_LIBS $curl_cv_save_LIBS"
      fi
      AC_MSG_RESULT([$curl_cv_ldap_LIBS])
      ;;
  esac
  #
])


dnl CURL_CHECK_LIBS_LDAP
dnl -------------------------------------------------
dnl Check for libraries needed for LDAP support,
dnl and prepended to LIBS any needed libraries.
dnl This macro can take an optional parameter with a
dnl white space separated list of libraries to check
dnl before the default ones.

AC_DEFUN([CURL_CHECK_LIBS_LDAP], [
  AC_REQUIRE([CURL_CHECK_HEADER_LDAP])dnl
  #
  AC_MSG_CHECKING([for LDAP libraries])
  #
  u_libs=""
  #
  ifelse($1,,,[
    for x_lib in $1; do
      case "$x_lib" in
        -l*)
          l_lib="$x_lib"
          ;;
        *)
          l_lib="-l$x_lib"
          ;;
      esac
      if test -z "$u_libs"; then
        u_libs="$l_lib"
      else
        u_libs="$u_libs $l_lib"
      fi
    done
  ])
  #
  curl_cv_save_LIBS=$LIBS
  curl_cv_ldap_LIBS="unknown"
  #
  for x_nlibs in '' "$u_libs" \
    '-lldap' \
    '-llber -lldap' \
    '-lldap -llber' \
    '-lldapssl -lldapx -lldapsdk' \
    '-lldapsdk -lldapx -lldapssl' ; do
    if test -z "$x_nlibs"; then
      LIBS="$curl_cv_save_LIBS"
    else
      LIBS="$x_nlibs $curl_cv_save_LIBS"
    fi
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#ifndef NULL
#define NULL (void *)0
#endif
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#ifdef NEED_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
      ],[
        BerValue *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        int res = ldap_unbind(ldp);
        ber_free(bep, 1);
      ])
    ],[
       curl_cv_ldap_LIBS="$x_nlibs"
       break
    ])
  done
  #
  LIBS=$curl_cv_save_LIBS
  #
  case X-"$curl_cv_ldap_LIBS" in
    X-unknown)
      AC_MSG_RESULT([cannot find LDAP libraries])
      ;;
    X-)
      AC_MSG_RESULT([no additional lib required])
      ;;
    *)
      if test -z "$curl_cv_save_LIBS"; then
        LIBS="$curl_cv_ldap_LIBS"
      else
        LIBS="$curl_cv_ldap_LIBS $curl_cv_save_LIBS"
      fi
      AC_MSG_RESULT([$curl_cv_ldap_LIBS])
      ;;
  esac
  #
])


dnl CURL_CHECK_HEADER_MALLOC
dnl -------------------------------------------------
dnl Check for compilable and valid malloc.h header,
dnl and check if it is needed even with stdlib.h

AC_DEFUN([CURL_CHECK_HEADER_MALLOC], [
  AC_CACHE_CHECK([for malloc.h], [ac_cv_header_malloc_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#include <malloc.h>
      ],[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ])
    ],[
      ac_cv_header_malloc_h="yes"
    ],[
      ac_cv_header_malloc_h="no"
    ])
  ])
  if test "$ac_cv_header_malloc_h" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_MALLOC_H, 1,
      [Define to 1 if you have the malloc.h header file.])
    #
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#include <stdlib.h>
      ],[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ])
    ],[
      curl_cv_need_header_malloc_h="no"
    ],[
      curl_cv_need_header_malloc_h="yes"
    ])
    #
    case "$curl_cv_need_header_malloc_h" in
      yes)
        AC_DEFINE_UNQUOTED(NEED_MALLOC_H, 1,
          [Define to 1 if you need the malloc.h header file even with stdlib.h])
        ;;
    esac
  fi
])


dnl CURL_CHECK_TYPE_SOCKLEN_T
dnl -------------------------------------------------
dnl Check for existing socklen_t type, and provide
dnl an equivalent type if socklen_t not available

AC_DEFUN([CURL_CHECK_TYPE_SOCKLEN_T], [
  AC_REQUIRE([CURL_CHECK_HEADER_WS2TCPIP])dnl
  AC_CHECK_TYPE([socklen_t], ,[
    AC_CACHE_CHECK([for socklen_t equivalent], 
      [curl_cv_socklen_t_equiv], [
      curl_cv_socklen_t_equiv="unknown"
      for arg2 in "struct sockaddr" void; do
        for t in int size_t unsigned long "unsigned long"; do
          AC_COMPILE_IFELSE([
            AC_LANG_PROGRAM([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
              int getpeername (int, $arg2 *, $t *);
            ],[
              $t len=0;
              getpeername(0,0,&len);
            ])
          ],[
             curl_cv_socklen_t_equiv="$t"
             break 2
          ])
        done
      done
    ])
    case "$curl_cv_socklen_t_equiv" in
      unknown)
        AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
        ;;
      *)
        AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
          [type to use in place of socklen_t if not defined])
        ;;
    esac
  ],[
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
  ])
])


dnl CURL_CHECK_FUNC_GETNAMEINFO
dnl -------------------------------------------------
dnl Test if the getnameinfo function is available, 
dnl and check the types of five of its arguments.
dnl If the function succeeds HAVE_GETNAMEINFO will be
dnl defined, defining the types of the arguments in
dnl GETNAMEINFO_TYPE_ARG1, GETNAMEINFO_TYPE_ARG2,
dnl GETNAMEINFO_TYPE_ARG46 and GETNAMEINFO_TYPE_ARG7,
dnl and also defining the type qualifier of first 
dnl argument in GETNAMEINFO_QUAL_ARG1.

AC_DEFUN([CURL_CHECK_FUNC_GETNAMEINFO], [
  AC_REQUIRE([CURL_CHECK_HEADER_WS2TCPIP])dnl
  AC_REQUIRE([CURL_CHECK_TYPE_SOCKLEN_T])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h netdb.h)
  #
  AC_MSG_CHECKING([for getnameinfo])
  AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([getnameinfo])
    ],[
      AC_MSG_RESULT([yes])
      curl_cv_getnameinfo="yes"
    ],[
      AC_MSG_RESULT([no])
      curl_cv_getnameinfo="no"
  ])
  #
  if test "$curl_cv_getnameinfo" != "yes"; then
    AC_MSG_CHECKING([deeper for getnameinfo])
    AC_TRY_LINK([
      ],[
        getnameinfo();
      ],[
        AC_MSG_RESULT([yes])
        curl_cv_getnameinfo="yes"
      ],[
        AC_MSG_RESULT([but still no])
        curl_cv_getnameinfo="no"
    ])
  fi
  #
  if test "$curl_cv_getnameinfo" != "yes"; then
    AC_MSG_CHECKING([deeper and deeper for getnameinfo])
    AC_TRY_LINK([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#endif
      ],[
        getnameinfo(0, 0, 0, 0, 0, 0, 0);
      ],[ 
        AC_MSG_RESULT([yes])
        curl_cv_getnameinfo="yes"
      ],[
        AC_MSG_RESULT([but still no])
        curl_cv_getnameinfo="no"
    ])
  fi
  #
  if test "$curl_cv_getnameinfo" = "yes"; then
    AC_CACHE_CHECK([types of arguments for getnameinfo],
      [curl_cv_func_getnameinfo_args], [
      curl_cv_func_getnameinfo_args="unknown"
      for gni_arg1 in 'struct sockaddr *' 'const struct sockaddr *' 'void *'; do
        for gni_arg2 in 'socklen_t' 'size_t' 'int'; do
          for gni_arg46 in 'size_t' 'int' 'socklen_t' 'unsigned int' 'DWORD'; do
            for gni_arg7 in 'int' 'unsigned int'; do
              AC_COMPILE_IFELSE([
                AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#if (!defined(_WIN32_WINNT)) || (_WIN32_WINNT < 0x0501)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h> 
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif
#define GNICALLCONV WSAAPI
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#define GNICALLCONV
#endif
                  extern int GNICALLCONV getnameinfo($gni_arg1, $gni_arg2,
                                         char *, $gni_arg46,
                                         char *, $gni_arg46,
                                         $gni_arg7);
                ],[
                  $gni_arg2 salen=0;
                  $gni_arg46 hostlen=0;
                  $gni_arg46 servlen=0;
                  $gni_arg7 flags=0;
                  int res = getnameinfo(0, salen, 0, hostlen, 0, servlen, flags);
                ])
              ],[
                 curl_cv_func_getnameinfo_args="$gni_arg1,$gni_arg2,$gni_arg46,$gni_arg7"
                 break 4
              ])
            done
          done
        done
      done
    ]) # AC_CACHE_CHECK
    if test "$curl_cv_func_getnameinfo_args" = "unknown"; then
      AC_MSG_WARN([Cannot find proper types to use for getnameinfo args])
      AC_MSG_WARN([HAVE_GETNAMEINFO will not be defined])
    else
      gni_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_getnameinfo_args" | sed 's/\*/\*/g'`
      IFS=$gni_prev_IFS
      shift
      #
      gni_qual_type_arg1=$[1]
      #
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG2, $[2],
        [Define to the type of arg 2 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG46, $[3],
        [Define to the type of args 4 and 6 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG7, $[4],
        [Define to the type of arg 7 for getnameinfo.])
      #
      prev_sh_opts=$-
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set -f
          ;;
      esac
      #
      case "$gni_qual_type_arg1" in
        const*)
          gni_qual_arg1=const
          gni_type_arg1=`echo $gni_qual_type_arg1 | sed 's/^const //'`
        ;;
        *)
          gni_qual_arg1=
          gni_type_arg1=$gni_qual_type_arg1
        ;;
      esac
      #
      AC_DEFINE_UNQUOTED(GETNAMEINFO_QUAL_ARG1, $gni_qual_arg1,
        [Define to the type qualifier of arg 1 for getnameinfo.])
      AC_DEFINE_UNQUOTED(GETNAMEINFO_TYPE_ARG1, $gni_type_arg1,
        [Define to the type of arg 1 for getnameinfo.])
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set +f
          ;;
      esac
      #
      AC_DEFINE_UNQUOTED(HAVE_GETNAMEINFO, 1,
        [Define to 1 if you have the getnameinfo function.])
      ac_cv_func_getnameinfo="yes"
    fi
  fi
]) # AC_DEFUN


dnl TYPE_SOCKADDR_STORAGE
dnl -------------------------------------------------
dnl Check for struct sockaddr_storage. Most IPv6-enabled 
dnl hosts have it, but AIX 4.3 is one known exception.

AC_DEFUN([TYPE_SOCKADDR_STORAGE],
[
   AC_CHECK_TYPE([struct sockaddr_storage],
        AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE, 1,
                  [if struct sockaddr_storage is defined]), ,
   [
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif
   ])
])


dnl CURL_CHECK_NI_WITHSCOPEID
dnl -------------------------------------------------
dnl Check for working NI_WITHSCOPEID in getnameinfo()

AC_DEFUN([CURL_CHECK_NI_WITHSCOPEID], [
  AC_REQUIRE([CURL_CHECK_FUNC_GETNAMEINFO])dnl
  AC_REQUIRE([TYPE_SOCKADDR_STORAGE])dnl
  AC_CHECK_HEADERS(stdio.h sys/types.h sys/socket.h \
                   netdb.h netinet/in.h arpa/inet.h)
  #
  AC_CACHE_CHECK([for working NI_WITHSCOPEID], 
    [ac_cv_working_ni_withscopeid], [
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
      ],[
#if defined(NI_WITHSCOPEID) && defined(HAVE_GETNAMEINFO)
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
        struct sockaddr_storage sa;
#else
        unsigned char sa[256];
#endif
        char hostbuf[NI_MAXHOST];
        int rc;
        GETNAMEINFO_TYPE_ARG2 salen = (GETNAMEINFO_TYPE_ARG2)sizeof(sa);
        GETNAMEINFO_TYPE_ARG46 hostlen = (GETNAMEINFO_TYPE_ARG46)sizeof(hostbuf);
        GETNAMEINFO_TYPE_ARG7 flags = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if(fd < 0) {
          perror("socket()");
          return 1; /* Error creating socket */
        }
        rc = getsockname(fd, (GETNAMEINFO_TYPE_ARG1)&sa, &salen);
        if(rc) {
          perror("getsockname()");
          return 2; /* Error retrieving socket name */
        }
        rc = getnameinfo((GETNAMEINFO_TYPE_ARG1)&sa, salen, hostbuf, hostlen, NULL, 0, flags);
        if(rc) {
          printf("rc = %s\n", gai_strerror(rc));
          return 3; /* Error translating socket address */
        }
        return 0; /* Ok, NI_WITHSCOPEID works */
#else
        return 4; /* Error, NI_WITHSCOPEID not defined or no getnameinfo() */
#endif
      ]) # AC_LANG_PROGRAM
    ],[
      # Exit code == 0. Program worked.
      ac_cv_working_ni_withscopeid="yes"
    ],[
      # Exit code != 0. Program failed.
      ac_cv_working_ni_withscopeid="no"
    ],[
      # Program is not run when cross-compiling. So we assume
      # NI_WITHSCOPEID will work if we are able to compile it.
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
        ],[
          unsigned int dummy= NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
        ])
      ],[
        ac_cv_working_ni_withscopeid="yes"
      ],[
        ac_cv_working_ni_withscopeid="no"
      ]) # AC_COMPILE_IFELSE
    ]) # AC_RUN_IFELSE
  ]) # AC_CACHE_CHECK
  case "$ac_cv_working_ni_withscopeid" in
    yes)
      AC_DEFINE(HAVE_NI_WITHSCOPEID, 1,
        [Define to 1 if NI_WITHSCOPEID exists and works.])
      ;;
  esac
]) # AC_DEFUN


dnl CURL_CHECK_FUNC_RECV
dnl -------------------------------------------------
dnl Test if the socket recv() function is available, 
dnl and check its return type and the types of its 
dnl arguments. If the function succeeds HAVE_RECV 
dnl will be defined, defining the types of the arguments 
dnl in RECV_TYPE_ARG1, RECV_TYPE_ARG2, RECV_TYPE_ARG3 
dnl and RECV_TYPE_ARG4, defining the type of the function
dnl return value in RECV_TYPE_RETV.

AC_DEFUN([CURL_CHECK_FUNC_RECV], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  #
  AC_MSG_CHECKING([for recv])
  AC_TRY_LINK([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
    ],[
      recv(0, 0, 0, 0);
    ],[ 
      AC_MSG_RESULT([yes])
      curl_cv_recv="yes"
    ],[
      AC_MSG_RESULT([no])
      curl_cv_recv="no"
  ])
  #
  if test "$curl_cv_recv" = "yes"; then
    AC_CACHE_CHECK([types of args and return type for recv],
      [curl_cv_func_recv_args], [
      curl_cv_func_recv_args="unknown"
      for recv_retv in 'int' 'ssize_t'; do
        for recv_arg1 in 'int' 'ssize_t' 'SOCKET'; do
          for recv_arg2 in 'char *' 'void *'; do
            for recv_arg3 in 'size_t' 'int' 'socklen_t' 'unsigned int'; do
              for recv_arg4 in 'int' 'unsigned int'; do
                AC_COMPILE_IFELSE([
                  AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#define RECVCALLCONV PASCAL
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#define RECVCALLCONV
#endif
                    extern $recv_retv RECVCALLCONV recv($recv_arg1, $recv_arg2, $recv_arg3, $recv_arg4);
                  ],[
                    $recv_arg1 s=0;
                    $recv_arg2 buf=0;
                    $recv_arg3 len=0;
                    $recv_arg4 flags=0;
                    $recv_retv res = recv(s, buf, len, flags);
                  ])
                ],[
                   curl_cv_func_recv_args="$recv_arg1,$recv_arg2,$recv_arg3,$recv_arg4,$recv_retv"
                   break 5
                ])
              done
            done
          done
        done
      done
    ]) # AC_CACHE_CHECK
    if test "$curl_cv_func_recv_args" = "unknown"; then
      AC_MSG_ERROR([Cannot find proper types to use for recv args])
    else
      recv_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_recv_args" | sed 's/\*/\*/g'`
      IFS=$recv_prev_IFS
      shift
      #
      AC_DEFINE_UNQUOTED(RECV_TYPE_ARG1, $[1],
        [Define to the type of arg 1 for recv.])
      AC_DEFINE_UNQUOTED(RECV_TYPE_ARG2, $[2],
        [Define to the type of arg 2 for recv.])
      AC_DEFINE_UNQUOTED(RECV_TYPE_ARG3, $[3],
        [Define to the type of arg 3 for recv.])
      AC_DEFINE_UNQUOTED(RECV_TYPE_ARG4, $[4],
        [Define to the type of arg 4 for recv.])
      AC_DEFINE_UNQUOTED(RECV_TYPE_RETV, $[5],
        [Define to the function return type for recv.])
      #
      AC_DEFINE_UNQUOTED(HAVE_RECV, 1,
        [Define to 1 if you have the recv function.])
      ac_cv_func_recv="yes"
    fi
  else
    AC_MSG_ERROR([Unable to link function recv])
  fi
]) # AC_DEFUN


dnl CURL_CHECK_FUNC_SEND
dnl -------------------------------------------------
dnl Test if the socket send() function is available, 
dnl and check its return type and the types of its 
dnl arguments. If the function succeeds HAVE_SEND 
dnl will be defined, defining the types of the arguments 
dnl in SEND_TYPE_ARG1, SEND_TYPE_ARG2, SEND_TYPE_ARG3 
dnl and SEND_TYPE_ARG4, defining the type of the function
dnl return value in SEND_TYPE_RETV, and also defining the 
dnl type qualifier of second argument in SEND_QUAL_ARG2.

AC_DEFUN([CURL_CHECK_FUNC_SEND], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  #
  AC_MSG_CHECKING([for send])
  AC_TRY_LINK([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
    ],[
      send(0, 0, 0, 0);
    ],[ 
      AC_MSG_RESULT([yes])
      curl_cv_send="yes"
    ],[
      AC_MSG_RESULT([no])
      curl_cv_send="no"
  ])
  #
  if test "$curl_cv_send" = "yes"; then
    AC_CACHE_CHECK([types of args and return type for send],
      [curl_cv_func_send_args], [
      curl_cv_func_send_args="unknown"
      for send_retv in 'int' 'ssize_t'; do
        for send_arg1 in 'int' 'ssize_t' 'SOCKET'; do
          for send_arg2 in 'char *' 'void *' 'const char *' 'const void *'; do
            for send_arg3 in 'size_t' 'int' 'socklen_t' 'unsigned int'; do
              for send_arg4 in 'int' 'unsigned int'; do
                AC_COMPILE_IFELSE([
                  AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#define SENDCALLCONV PASCAL
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#define SENDCALLCONV
#endif
                    extern $send_retv SENDCALLCONV send($send_arg1, $send_arg2, $send_arg3, $send_arg4);
                  ],[
                    $send_arg1 s=0;
                    $send_arg3 len=0;
                    $send_arg4 flags=0;
                    $send_retv res = send(s, 0, len, flags);
                  ])
                ],[
                   curl_cv_func_send_args="$send_arg1,$send_arg2,$send_arg3,$send_arg4,$send_retv"
                   break 5
                ])
              done
            done
          done
        done
      done
    ]) # AC_CACHE_CHECK
    if test "$curl_cv_func_send_args" = "unknown"; then
      AC_MSG_ERROR([Cannot find proper types to use for send args])
    else
      send_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_send_args" | sed 's/\*/\*/g'`
      IFS=$send_prev_IFS
      shift
      #
      send_qual_type_arg2=$[2]
      #
      AC_DEFINE_UNQUOTED(SEND_TYPE_ARG1, $[1],
        [Define to the type of arg 1 for send.])
      AC_DEFINE_UNQUOTED(SEND_TYPE_ARG3, $[3],
        [Define to the type of arg 3 for send.])
      AC_DEFINE_UNQUOTED(SEND_TYPE_ARG4, $[4],
        [Define to the type of arg 4 for send.])
      AC_DEFINE_UNQUOTED(SEND_TYPE_RETV, $[5],
        [Define to the function return type for send.])
      #
      prev_sh_opts=$-
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set -f
          ;;
      esac
      #
      case "$send_qual_type_arg2" in
        const*)
          send_qual_arg2=const
          send_type_arg2=`echo $send_qual_type_arg2 | sed 's/^const //'`
        ;;
        *)
          send_qual_arg2=
          send_type_arg2=$send_qual_type_arg2
        ;;
      esac
      #
      AC_DEFINE_UNQUOTED(SEND_QUAL_ARG2, $send_qual_arg2,
        [Define to the type qualifier of arg 2 for send.])
      AC_DEFINE_UNQUOTED(SEND_TYPE_ARG2, $send_type_arg2,
        [Define to the type of arg 2 for send.])
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set +f
          ;;
      esac
      #
      AC_DEFINE_UNQUOTED(HAVE_SEND, 1,
        [Define to 1 if you have the send function.])
      ac_cv_func_send="yes"
    fi
  else
    AC_MSG_ERROR([Unable to link function send])
  fi
]) # AC_DEFUN


dnl CURL_CHECK_MSG_NOSIGNAL
dnl -------------------------------------------------
dnl Check for MSG_NOSIGNAL

AC_DEFUN([CURL_CHECK_MSG_NOSIGNAL], [
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  AC_CACHE_CHECK([for MSG_NOSIGNAL], [ac_cv_msg_nosignal], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
      ],[
        int flag=MSG_NOSIGNAL;
      ])
    ],[
      ac_cv_msg_nosignal="yes"
    ],[
      ac_cv_msg_nosignal="no"
    ])
  ])
  case "$ac_cv_msg_nosignal" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_MSG_NOSIGNAL, 1,
        [Define to 1 if you have the MSG_NOSIGNAL flag.])
      ;;
  esac
]) # AC_DEFUN


dnl CURL_CHECK_STRUCT_TIMEVAL
dnl -------------------------------------------------
dnl Check for timeval struct

AC_DEFUN([CURL_CHECK_STRUCT_TIMEVAL], [
  AC_REQUIRE([AC_HEADER_TIME])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CHECK_HEADERS(sys/types.h sys/time.h time.h)
  AC_CACHE_CHECK([for struct timeval], [ac_cv_struct_timeval], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#undef inline 
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#endif
      ],[
        struct timeval ts;
        ts.tv_sec  = 0;
        ts.tv_usec = 0;
      ])
    ],[
      ac_cv_struct_timeval="yes"
    ],[
      ac_cv_struct_timeval="no"
    ])
  ])
  case "$ac_cv_struct_timeval" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_STRUCT_TIMEVAL, 1,
        [Define to 1 if you have the timeval struct.])
      ;;
  esac
]) # AC_DEFUN


dnl TYPE_SIG_ATOMIC_T
dnl -------------------------------------------------
dnl Check if the sig_atomic_t type is available, and
dnl verify if it is already defined as volatile.

AC_DEFUN([TYPE_SIG_ATOMIC_T], [
  AC_CHECK_HEADERS(signal.h)
  AC_CHECK_TYPE([sig_atomic_t],[
    AC_DEFINE(HAVE_SIG_ATOMIC_T, 1,
      [Define to 1 if sig_atomic_t is an available typedef.])
  ], ,[
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
  ])
  case "$ac_cv_type_sig_atomic_t" in
    yes)
      #
      AC_MSG_CHECKING([if sig_atomic_t is already defined as volatile])
      AC_TRY_LINK([
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
        ],[
          static volatile sig_atomic_t dummy = 0;
        ],[ 
          AC_MSG_RESULT([no])
          ac_cv_sig_atomic_t_volatile="no"
        ],[
          AC_MSG_RESULT([yes])
          ac_cv_sig_atomic_t_volatile="yes"
      ])
      #
      if test "$ac_cv_sig_atomic_t_volatile" = "yes"; then
        AC_DEFINE(HAVE_SIG_ATOMIC_T_VOLATILE, 1,
          [Define to 1 if sig_atomic_t is already defined as volatile.])
      fi
      ;;
  esac
]) # AC_DEFUN


dnl CURL_CHECK_NONBLOCKING_SOCKET
dnl -------------------------------------------------
dnl Check for how to set a socket to non-blocking state. There seems to exist
dnl four known different ways, with the one used almost everywhere being POSIX
dnl and XPG3, while the other different ways for different systems (old BSD,
dnl Windows and Amiga).
dnl
dnl There are two known platforms (AIX 3.x and SunOS 4.1.x) where the
dnl O_NONBLOCK define is found but does not work. This condition is attempted
dnl to get caught in this script by using an excessive number of #ifdefs...
dnl
AC_DEFUN([CURL_CHECK_NONBLOCKING_SOCKET],
[
  AC_MSG_CHECKING([non-blocking sockets style])

  AC_TRY_COMPILE([
/* headers for O_NONBLOCK test */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
],[
/* try to compile O_NONBLOCK */

#if defined(sun) || defined(__sun__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# if defined(__SVR4) || defined(__srv4__)
#  define PLATFORM_SOLARIS
# else
#  define PLATFORM_SUNOS4
# endif
#endif
#if (defined(_AIX) || defined(__xlC__)) && !defined(_AIX41)
# define PLATFORM_AIX_V3
#endif

#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3) || defined(__BEOS__)
#error "O_NONBLOCK does not work on this platform"
#endif
  int socket;
  int flags = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
],[
dnl the O_NONBLOCK test was fine
nonblock="O_NONBLOCK"
AC_DEFINE(HAVE_O_NONBLOCK, 1, [use O_NONBLOCK for non-blocking sockets])
],[
dnl the code was bad, try a different program now, test 2

  AC_TRY_COMPILE([
/* headers for FIONBIO test */
#include <unistd.h>
#include <stropts.h>
],[
/* FIONBIO source test (old-style unix) */
 int socket;
 int flags = ioctl(socket, FIONBIO, &flags);
],[
dnl FIONBIO test was good
nonblock="FIONBIO"
AC_DEFINE(HAVE_FIONBIO, 1, [use FIONBIO for non-blocking sockets])
],[
dnl FIONBIO test was also bad
dnl the code was bad, try a different program now, test 3

  AC_TRY_COMPILE([
/* headers for ioctlsocket test (Windows) */
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#endif
],[
/* ioctlsocket source code */
 SOCKET sd;
 unsigned long flags = 0;
 sd = socket(0, 0, 0);
 ioctlsocket(sd, FIONBIO, &flags);
],[
dnl ioctlsocket test was good
nonblock="ioctlsocket"
AC_DEFINE(HAVE_IOCTLSOCKET, 1, [use ioctlsocket() for non-blocking sockets])
],[
dnl ioctlsocket didnt compile!, go to test 4

  AC_TRY_LINK([
/* headers for IoctlSocket test (Amiga?) */
#include <sys/ioctl.h>
],[
/* IoctlSocket source code */
 int socket;
 int flags = IoctlSocket(socket, FIONBIO, (long)1);
],[
dnl ioctlsocket test was good
nonblock="IoctlSocket"
AC_DEFINE(HAVE_IOCTLSOCKET_CASE, 1, [use Ioctlsocket() for non-blocking sockets])
],[
dnl Ioctlsocket didnt compile, do test 5!
  AC_TRY_COMPILE([
/* headers for SO_NONBLOCK test (BeOS) */
#include <socket.h>
],[
/* SO_NONBLOCK source code */
 long b = 1;
 int socket;
 int flags = setsockopt(socket, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
],[
dnl the SO_NONBLOCK test was good
nonblock="SO_NONBLOCK"
AC_DEFINE(HAVE_SO_NONBLOCK, 1, [use SO_NONBLOCK for non-blocking sockets])
],[
dnl test 5 didnt compile!
nonblock="nada"
AC_DEFINE(HAVE_DISABLED_NONBLOCKING, 1, [disabled non-blocking sockets])
])
dnl end of fifth test

])
dnl end of forth test

])
dnl end of third test

])
dnl end of second test

])
dnl end of non-blocking try-compile test
  AC_MSG_RESULT($nonblock)

  if test "$nonblock" = "nada"; then
    AC_MSG_WARN([non-block sockets disabled])
  fi
])


dnl TYPE_IN_ADDR_T
dnl -------------------------------------------------
dnl Check for in_addr_t: it is used to receive the return code of inet_addr()
dnl and a few other things.
AC_DEFUN([TYPE_IN_ADDR_T],
[
   AC_CHECK_TYPE([in_addr_t], ,[
      AC_MSG_CHECKING([for in_addr_t equivalent])
      AC_CACHE_VAL([curl_cv_in_addr_t_equiv],
      [
         curl_cv_in_addr_t_equiv=
         for t in "unsigned long" int size_t unsigned long; do
            AC_TRY_COMPILE([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif
            ],[
               $t data = inet_addr ("1.2.3.4");
            ],[
               curl_cv_in_addr_t_equiv="$t"
               break
            ])
         done

         if test "x$curl_cv_in_addr_t_equiv" = x; then
            AC_MSG_ERROR([Cannot find a type to use in place of in_addr_t])
         fi
      ])
      AC_MSG_RESULT($curl_cv_in_addr_t_equiv)
      AC_DEFINE_UNQUOTED(in_addr_t, $curl_cv_in_addr_t_equiv,
			[type to use in place of in_addr_t if not defined])],
      [
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif
  ]) dnl AC_CHECK_TYPE
]) dnl AC_DEFUN

dnl ************************************************************
dnl check for "localhost", if it doesn't exist, we can't do the
dnl gethostbyname_r tests!
dnl 

AC_DEFUN([CURL_CHECK_WORKING_RESOLVER],[
AC_MSG_CHECKING([if "localhost" resolves])
AC_TRY_RUN([
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#ifndef NULL
#define NULL (void *)0
#endif

int
main () {
struct hostent *h;
h = gethostbyname("localhost");
exit (h == NULL ? 1 : 0); }],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_ERROR([can't figure out gethostbyname_r() since localhost doesn't resolve])

      ]
)
])

dnl ************************************************************
dnl check for working getaddrinfo() that works with AI_NUMERICHOST
dnl
AC_DEFUN([CURL_CHECK_WORKING_GETADDRINFO],[
  AC_CACHE_CHECK(for working getaddrinfo, ac_cv_working_getaddrinfo,[
  AC_TRY_RUN( [
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(void)
{
    struct addrinfo hints, *ai;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo("127.0.0.1", "8080", &hints, &ai);
    if (error) {
        return 1;
    }
    return 0;
}
],[
  ac_cv_working_getaddrinfo="yes"
],[
  ac_cv_working_getaddrinfo="no"
],[
  ac_cv_working_getaddrinfo="yes"
])])
if test "$ac_cv_working_getaddrinfo" = "yes"; then
  AC_DEFINE(HAVE_GETADDRINFO, 1, [Define if getaddrinfo exists and works])
  AC_DEFINE(ENABLE_IPV6, 1, [Define if you want to enable IPv6 support])

  IPV6_ENABLED=1
  AC_SUBST(IPV6_ENABLED)
fi
])


AC_DEFUN([CURL_CHECK_LOCALTIME_R],
[
  dnl check for localtime_r
  AC_CHECK_FUNCS(localtime_r,[
    AC_MSG_CHECKING(whether localtime_r is declared)
    AC_EGREP_CPP(localtime_r,[
#include <time.h>],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether localtime_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(localtime_r,[
#define _REENTRANT
#include <time.h>],[
	AC_DEFINE(NEED_REENTRANT)
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])
])

dnl
dnl This function checks for strerror_r(). If it isn't found at first, it
dnl retries with _THREAD_SAFE defined, as that is what AIX seems to require
dnl in order to find this function.
dnl
dnl If the function is found, it will then proceed to check how the function
dnl actually works: glibc-style or POSIX-style.
dnl
dnl glibc:
dnl      char *strerror_r(int errnum, char *buf, size_t n);
dnl  
dnl  What this one does is to return the error string (no surprises there),
dnl  but it doesn't usually copy anything into buf!  The 'buf' and 'n'
dnl  parameters are only meant as an optional working area, in case strerror_r
dnl  needs it.  A quick test on a few systems shows that it's generally not
dnl  touched at all.
dnl
dnl POSIX:
dnl      int strerror_r(int errnum, char *buf, size_t n);
dnl
AC_DEFUN([CURL_CHECK_STRERROR_R],
[
  AC_CHECK_FUNCS(strerror_r)

  if test "x$ac_cv_func_strerror_r" = "xyes"; then

    AC_MSG_CHECKING(whether strerror_r is declared)
    AC_EGREP_CPP(strerror_r,[
#include <string.h>],[
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether strerror_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(strerror_r,[
#define _REENTRANT
#include <string.h>],[
	CPPFLAGS="-D_REENTRANT $CPPFLAGS"
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no)
        AC_DEFINE(HAVE_NO_STRERROR_R_DECL, 1, [we have no strerror_r() proto])
       ) dnl with _THREAD_SAFE
    ]) dnl plain cpp for it

    dnl determine if this strerror_r() is glibc or POSIX
    AC_MSG_CHECKING([for a glibc strerror_r API])
    AC_TRY_RUN([
#include <string.h>
#include <errno.h>
int
main () {
  char buffer[1024]; /* big enough to play with */
  char *string =
    strerror_r(EACCES, buffer, sizeof(buffer));
    /* this should've returned a string */
    if(!string || !string[0])
      return 99;
    return 0;
}
],
    GLIBC_STRERROR_R="1"
    AC_DEFINE(HAVE_GLIBC_STRERROR_R, 1, [we have a glibc-style strerror_r()])
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no]),

    dnl Use an inferior method of strerror_r detection while cross-compiling
    AC_EGREP_CPP(yes, [
#include <features.h>
#ifdef __GLIBC__
yes
#endif
], 
      dnl looks like glibc, so assume a glibc-style strerror_r()
      GLIBC_STRERROR_R="1"
      AC_DEFINE(HAVE_GLIBC_STRERROR_R, 1, [we have a glibc-style strerror_r()])
      AC_MSG_RESULT([yes]),
      AC_MSG_NOTICE([cannot determine strerror_r() style: edit lib/config.h manually!])
    ) dnl while cross-compiling
    )

    if test -z "$GLIBC_STRERROR_R"; then

      AC_MSG_CHECKING([for a POSIX strerror_r API])
      AC_TRY_RUN([
#include <string.h>
#include <errno.h>
int
main () {
  char buffer[1024]; /* big enough to play with */
  int error =
    strerror_r(EACCES, buffer, sizeof(buffer));
    /* This should've returned zero, and written an error string in the
       buffer.*/
    if(!buffer[0] || error)
      return 99;
    return 0;
}
],
      AC_DEFINE(HAVE_POSIX_STRERROR_R, 1, [we have a POSIX-style strerror_r()])
      AC_MSG_RESULT([yes]),
      AC_MSG_RESULT([no]) ,
      dnl cross-compiling!
      AC_MSG_NOTICE([cannot determine strerror_r() style: edit lib/config.h manually!])
    )

    fi dnl if not using glibc API

  fi dnl we have a strerror_r

])

AC_DEFUN([CURL_CHECK_INET_NTOA_R],
[
  dnl determine if function definition for inet_ntoa_r exists.
  AC_CHECK_FUNCS(inet_ntoa_r,[
    AC_MSG_CHECKING(whether inet_ntoa_r is declared)
    AC_EGREP_CPP(inet_ntoa_r,[
#include <arpa/inet.h>],[
      AC_DEFINE(HAVE_INET_NTOA_R_DECL, 1, [inet_ntoa_r() is declared])
      AC_MSG_RESULT(yes)],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(whether inet_ntoa_r with -D_REENTRANT is declared)
      AC_EGREP_CPP(inet_ntoa_r,[
#define _REENTRANT
#include <arpa/inet.h>],[
	AC_DEFINE(HAVE_INET_NTOA_R_DECL, 1, [inet_ntoa_r() is declared])
	AC_DEFINE(NEED_REENTRANT, 1, [need REENTRANT defined])
	AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no))])])
])

AC_DEFUN([CURL_CHECK_GETHOSTBYADDR_R],
[
  dnl check for number of arguments to gethostbyaddr_r. it might take
  dnl either 5, 7, or 8 arguments.
  AC_CHECK_FUNCS(gethostbyaddr_r,[
    AC_MSG_CHECKING(if gethostbyaddr_r takes 5 arguments)
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_GETHOSTBYADDR_R_5, 1, [gethostbyaddr_r() takes 5 args])
      ac_cv_gethostbyaddr_args=5],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(if gethostbyaddr_r with -D_REENTRANT takes 5 arguments)
      AC_TRY_COMPILE([
#define _REENTRANT
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
struct hostent_data hdata;
int rc;
rc = gethostbyaddr_r(address, length, type, &h, &hdata);],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_GETHOSTBYADDR_R_5, 1, [gethostbyaddr_r() takes 5 args])
	AC_DEFINE(NEED_REENTRANT, 1, [need REENTRANT])
	ac_cv_gethostbyaddr_args=5],[
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING(if gethostbyaddr_r takes 7 arguments)
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;

hp = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &h_errnop);],[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_GETHOSTBYADDR_R_7, 1, [gethostbyaddr_r() takes 7 args] )
	  ac_cv_gethostbyaddr_args=7],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING(if gethostbyaddr_r takes 8 arguments)
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>],[
char * address;
int length;
int type;
struct hostent h;
char buffer[8192];
int h_errnop;
struct hostent * hp;
int rc;

rc = gethostbyaddr_r(address, length, type, &h,
                     buffer, 8192, &hp, &h_errnop);],[
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_GETHOSTBYADDR_R_8, 1, [gethostbyaddr_r() takes 8 args])
	    ac_cv_gethostbyaddr_args=8],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyaddr_r"])])])])])
])

AC_DEFUN([CURL_CHECK_GETHOSTBYNAME_R],
[
  dnl check for number of arguments to gethostbyname_r. it might take
  dnl either 3, 5, or 6 arguments.
  AC_CHECK_FUNCS(gethostbyname_r,[
    AC_MSG_CHECKING([if gethostbyname_r takes 3 arguments])
    AC_TRY_COMPILE([
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *, struct hostent *, struct hostent_data *);],[
struct hostent_data data;
gethostbyname_r(NULL, NULL, NULL);],[
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_3, 1, [gethostbyname_r() takes 3 args])
      ac_cv_gethostbyname_args=3],[
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING([if gethostbyname_r with -D_REENTRANT takes 3 arguments])
      AC_TRY_COMPILE([
#define _REENTRANT

#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *,struct hostent *, struct hostent_data *);],[
struct hostent_data data;
gethostbyname_r(NULL, NULL, NULL);],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_GETHOSTBYNAME_R_3, 1, [gethostbyname_r() takes 3 args])
	AC_DEFINE(NEED_REENTRANT, 1, [needs REENTRANT])
	ac_cv_gethostbyname_args=3],[
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([if gethostbyname_r takes 5 arguments])
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

struct hostent *
gethostbyname_r(const char *, struct hostent *, char *, int, int *);],[
gethostbyname_r(NULL, NULL, NULL, 0, NULL);],[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_GETHOSTBYNAME_R_5, 1, [gethostbyname_r() takes 5 args])
          ac_cv_gethostbyname_args=5],[
	  AC_MSG_RESULT(no)
	  AC_MSG_CHECKING([if gethostbyname_r takes 6 arguments])
	  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netdb.h>
#undef NULL
#define NULL (void *)0

int
gethostbyname_r(const char *, struct hostent *, char *, size_t,
struct hostent **, int *);],[
gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL);],[
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_GETHOSTBYNAME_R_6, 1, [gethostbyname_r() takes 6 args])
            ac_cv_gethostbyname_args=6],[
	    AC_MSG_RESULT(no)
	    have_missing_r_funcs="$have_missing_r_funcs gethostbyname_r"],
	    [ac_cv_gethostbyname_args=0])],
	  [ac_cv_gethostbyname_args=0])],
	[ac_cv_gethostbyname_args=0])],
      [ac_cv_gethostbyname_args=0])])

if test "$ac_cv_func_gethostbyname_r" = "yes"; then
  if test "$ac_cv_gethostbyname_args" = "0"; then
    dnl there's a gethostbyname_r() function, but we don't know how
    dnl many arguments it wants!
    AC_MSG_ERROR([couldn't figure out how to use gethostbyname_r()])
  fi
fi
])


dnl **********************************************************************
dnl CURL_DETECT_ICC ([ACTION-IF-YES])
dnl
dnl check if this is the Intel ICC compiler, and if so run the ACTION-IF-YES
dnl sets the $ICC variable to "yes" or "no"
dnl **********************************************************************
AC_DEFUN([CURL_DETECT_ICC],
[
    ICC="no"
    AC_MSG_CHECKING([for icc in use])
    if test "$GCC" = "yes"; then
       dnl check if this is icc acting as gcc in disguise
       AC_EGREP_CPP([^__INTEL_COMPILER], [__INTEL_COMPILER],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         ICC="no",
         dnl the text was not found, it was replaced by the cpp
         ICC="yes"
         AC_MSG_RESULT([yes])
         [$1]
       )
    fi
    if test "$ICC" = "no"; then
        # this is not ICC
        AC_MSG_RESULT([no])
    fi
])

dnl We create a function for detecting which compiler we use and then set as
dnl pendantic compiler options as possible for that particular compiler. The
dnl options are only used for debug-builds.

AC_DEFUN([CURL_CC_DEBUG_OPTS],
[
    if test "z$ICC" = "z"; then
      CURL_DETECT_ICC
    fi

    if test "$GCC" = "yes"; then

       dnl figure out gcc version!
       AC_MSG_CHECKING([gcc version])
       gccver=`$CC -dumpversion`
       num1=`echo $gccver | cut -d . -f1`
       num2=`echo $gccver | cut -d . -f2`
       gccnum=`(expr $num1 "*" 100 + $num2) 2>/dev/null`
       AC_MSG_RESULT($gccver)

       if test "$ICC" = "yes"; then
         dnl this is icc, not gcc.

         dnl ICC warnings we ignore:
         dnl * 269 warns on our "%Od" printf formatters for curl_off_t output:
         dnl   "invalid format string conversion"
         dnl * 279 warns on static conditions in while expressions
         dnl * 981 warns on "operands are evaluated in unspecified order"
         dnl * 1418 "external definition with no prior declaration"
         dnl * 1419 warns on "external declaration in primary source file"
         dnl   which we know and do on purpose.

         WARN="-wd279,269,981,1418,1419"

         if test "$gccnum" -gt "600"; then
            dnl icc 6.0 and older doesn't have the -Wall flag
            WARN="-Wall $WARN"
         fi
       else dnl $ICC = yes
         dnl this is a set of options we believe *ALL* gcc versions support:
         WARN="-W -Wall -Wwrite-strings -pedantic -Wpointer-arith -Wnested-externs -Winline -Wmissing-prototypes"

         dnl -Wcast-align is a bit too annoying on all gcc versions ;-)

         if test "$gccnum" -ge "207"; then
           dnl gcc 2.7 or later
           WARN="$WARN -Wmissing-declarations"
         fi

         if test "$gccnum" -gt "295"; then
           dnl only if the compiler is newer than 2.95 since we got lots of
           dnl "`_POSIX_C_SOURCE' is not defined" in system headers with
           dnl gcc 2.95.4 on FreeBSD 4.9!
           WARN="$WARN -Wundef -Wno-long-long -Wsign-compare -Wshadow -Wno-multichar"
         fi

         if test "$gccnum" -ge "296"; then
           dnl gcc 2.96 or later
           WARN="$WARN -Wfloat-equal"
         fi

         if test "$gccnum" -gt "296"; then
           dnl this option does not exist in 2.96
           WARN="$WARN -Wno-format-nonliteral"
         fi

         dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
         dnl on i686-Linux as it gives us heaps with false positives.
         dnl Also, on gcc 4.0.X it is totally unbearable and complains all
         dnl over making it unusable for generic purposes. Let's not use it.

         if test "$gccnum" -ge "303"; then
           dnl gcc 3.3 and later
           WARN="$WARN -Wendif-labels -Wstrict-prototypes"
         fi

         if test "$gccnum" -ge "304"; then
           # try these on gcc 3.4
           WARN="$WARN -Wdeclaration-after-statement"
         fi

         for flag in $CPPFLAGS; do
           case "$flag" in
            -I*)
              dnl Include path, provide a -isystem option for the same dir
              dnl to prevent warnings in those dirs. The -isystem was not very
              dnl reliable on earlier gcc versions.
              add=`echo $flag | sed 's/^-I/-isystem /g'`
              WARN="$WARN $add"
              ;;
           esac
         done

       fi dnl $ICC = no

       CFLAGS="$CFLAGS $WARN"

      AC_MSG_NOTICE([Added this set of compiler options: $WARN])

    else dnl $GCC = yes

      AC_MSG_NOTICE([Added no extra compiler options])

    fi dnl $GCC = yes

    dnl strip off optimizer flags
    NEWFLAGS=""
    for flag in $CFLAGS; do
      case "$flag" in
      -O*)
        dnl echo "cut off $flag"
        ;;
      *)
        NEWFLAGS="$NEWFLAGS $flag"
        ;;
      esac
    done
    CFLAGS=$NEWFLAGS

]) dnl end of AC_DEFUN()

# This is only a temporary fix. This macro is here to replace the broken one
# delivered by the automake project (including the 1.9.6 release). As soon as
# they ship a working version we SHOULD remove this work-around.

AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
test x"${MISSING+set}" = xset || MISSING="\${SHELL} \"$am_aux_dir/missing\""
# Use eval to expand $SHELL
if eval "$MISSING --run true"; then
  am_missing_run="$MISSING --run "
else
  am_missing_run=
  AC_MSG_WARN([`missing' script is too old or missing])
fi
])


dnl CURL_VERIFY_RUNTIMELIBS
dnl -------------------------------------------------
dnl Verify that the shared libs found so far can be used when running
dnl programs, since otherwise the situation will create odd configure errors
dnl that are misleading people.
dnl
dnl Make sure this test is run BEFORE the first test in the script that
dnl runs anything, which at the time of this writing is the AC_CHECK_SIZEOF
dnl macro. It must also run AFTER all lib-checking macros are complete.

AC_DEFUN([CURL_VERIFY_RUNTIMELIBS], [

  dnl this test is of course not sensible if we are cross-compiling!
  if test "x$cross_compiling" != xyes; then

    dnl just run a program to verify that the libs checked for previous to this
    dnl point also is available run-time!
    AC_MSG_CHECKING([run-time libs availability])
    AC_TRY_RUN([
main()
{
  return 0;
}
],
    AC_MSG_RESULT([fine]),
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([one or more libs available at link-time are not available run-time. Libs used at link-time: $LIBS])
    )

    dnl if this test fails, configure has already stopped
  fi
])


dnl CURL_CHECK_VARIADIC_MACROS
dnl -------------------------------------------------
dnl Check compiler support of variadic macros

AC_DEFUN([CURL_CHECK_VARIADIC_MACROS], [
  AC_CACHE_CHECK([for compiler support of C99 variadic macro style],
    [curl_cv_variadic_macros_c99], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#define c99_vmacro3(first, ...) fun3(first, __VA_ARGS__)
#define c99_vmacro2(first, ...) fun2(first, __VA_ARGS__)
        int fun3(int arg1, int arg2, int arg3);
        int fun2(int arg1, int arg2);
        int fun3(int arg1, int arg2, int arg3)
        { return arg1 + arg2 + arg3; }
        int fun2(int arg1, int arg2)
        { return arg1 + arg2; }
      ],[
        int res3 = c99_vmacro3(1, 2, 3);
        int res2 = c99_vmacro2(1, 2);
      ])
    ],[
      curl_cv_variadic_macros_c99="yes"
    ],[
      curl_cv_variadic_macros_c99="no"
    ])
  ])
  case "$curl_cv_variadic_macros_c99" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_VARIADIC_MACROS_C99, 1,
        [Define to 1 if compiler supports C99 variadic macro style.])
      ;;
  esac
  AC_CACHE_CHECK([for compiler support of old gcc variadic macro style],
    [curl_cv_variadic_macros_gcc], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([
#define gcc_vmacro3(first, args...) fun3(first, args)
#define gcc_vmacro2(first, args...) fun2(first, args)
        int fun3(int arg1, int arg2, int arg3);
        int fun2(int arg1, int arg2);
        int fun3(int arg1, int arg2, int arg3)
        { return arg1 + arg2 + arg3; }
        int fun2(int arg1, int arg2)
        { return arg1 + arg2; }
      ],[
        int res3 = gcc_vmacro3(1, 2, 3);
        int res2 = gcc_vmacro2(1, 2);
      ])
    ],[
      curl_cv_variadic_macros_gcc="yes"
    ],[
      curl_cv_variadic_macros_gcc="no"
    ])
  ])
  case "$curl_cv_variadic_macros_gcc" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_VARIADIC_MACROS_GCC, 1,
        [Define to 1 if compiler supports old gcc variadic macro style.])
      ;;
  esac
])


dnl CURL_CHECK_NATIVE_WINDOWS
dnl -------------------------------------------------
dnl Check if building a native Windows target

AC_DEFUN([CURL_CHECK_NATIVE_WINDOWS], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([whether build target is a native Windows one], [ac_cv_native_windows], [
    if test "$ac_cv_header_windows_h" = "no"; then
      ac_cv_native_windows="no"
    else
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([
        ],[
#ifdef __MINGW32__
          int dummy=1;
#else
          Not a native Windows build target.
#endif
        ])
      ],[
        ac_cv_native_windows="yes"
      ],[
        ac_cv_native_windows="no"
      ])
    fi
  ])
  case "$ac_cv_native_windows" in
    yes)
      AC_DEFINE_UNQUOTED(NATIVE_WINDOWS, 1,
        [Define to 1 if you are building a native Windows target.])
      ;;
  esac
])

