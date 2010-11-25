#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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


dnl CURL_CHECK_DEF (SYMBOL, [INCLUDES], [SILENT])
dnl -------------------------------------------------
dnl Use the C preprocessor to find out if the given object-style symbol
dnl is defined and get its expansion. This macro will not use default
dnl includes even if no INCLUDES argument is given. This macro will run
dnl silently when invoked with three arguments. If the expansion would
dnl result in a set of double-quoted strings the returned expansion will
dnl actually be a single double-quoted string concatenating all them.

AC_DEFUN([CURL_CHECK_DEF], [
  AS_VAR_PUSHDEF([ac_HaveDef], [curl_cv_have_def_$1])dnl
  AS_VAR_PUSHDEF([ac_Def], [curl_cv_def_$1])dnl
  if test -z "$SED"; then
    AC_MSG_ERROR([SED not set. Cannot continue without SED being set.])
  fi
  if test -z "$GREP"; then
    AC_MSG_ERROR([GREP not set. Cannot continue without GREP being set.])
  fi
  ifelse($3,,[AC_MSG_CHECKING([for preprocessor definition of $1])])
  tmp_exp=""
  AC_PREPROC_IFELSE([
    AC_LANG_SOURCE(
ifelse($2,,,[$2])[[
#ifdef $1
CURL_DEF_TOKEN $1
#endif
    ]])
  ],[
    tmp_exp=`eval "$ac_cpp conftest.$ac_ext" 2>/dev/null | \
      "$GREP" CURL_DEF_TOKEN 2>/dev/null | \
      "$SED" 's/.*CURL_DEF_TOKEN[[ ]]//' 2>/dev/null | \
      "$SED" 's/[["]][[ ]]*[["]]//g' 2>/dev/null`
    if test -z "$tmp_exp" || test "$tmp_exp" = "$1"; then
      tmp_exp=""
    fi
  ])
  if test -z "$tmp_exp"; then
    AS_VAR_SET(ac_HaveDef, no)
    ifelse($3,,[AC_MSG_RESULT([no])])
  else
    AS_VAR_SET(ac_HaveDef, yes)
    AS_VAR_SET(ac_Def, $tmp_exp)
    ifelse($3,,[AC_MSG_RESULT([$tmp_exp])])
  fi
  AS_VAR_POPDEF([ac_Def])dnl
  AS_VAR_POPDEF([ac_HaveDef])dnl
])


dnl CURL_CHECK_DEF_CC (SYMBOL, [INCLUDES], [SILENT])
dnl -------------------------------------------------
dnl Use the C compiler to find out only if the given symbol is defined
dnl or not, this can not find out its expansion. This macro will not use
dnl default includes even if no INCLUDES argument is given. This macro
dnl will run silently when invoked with three arguments.

AC_DEFUN([CURL_CHECK_DEF_CC], [
  AS_VAR_PUSHDEF([ac_HaveDef], [curl_cv_have_def_$1])dnl
  ifelse($3,,[AC_MSG_CHECKING([for compiler definition of $1])])
  AC_COMPILE_IFELSE([
    AC_LANG_SOURCE(
ifelse($2,,,[$2])[[
int main (void)
{
#ifdef $1
  return 0;
#else
  force compilation error
#endif
}
    ]])
  ],[
    tst_symbol_defined="yes"
  ],[
    tst_symbol_defined="no"
  ])
  if test "$tst_symbol_defined" = "yes"; then
    AS_VAR_SET(ac_HaveDef, yes)
    ifelse($3,,[AC_MSG_RESULT([yes])])
  else
    AS_VAR_SET(ac_HaveDef, no)
    ifelse($3,,[AC_MSG_RESULT([no])])
  fi
  AS_VAR_POPDEF([ac_HaveDef])dnl
])


dnl CURL_CHECK_LIB_XNET
dnl -------------------------------------------------
dnl Verify if X/Open network library is required.

AC_DEFUN([CURL_CHECK_LIB_XNET], [
  AC_MSG_CHECKING([if X/Open network library is required])
  tst_lib_xnet_required="no"
  AC_COMPILE_IFELSE([
    AC_LANG_SOURCE([[
int main (void)
{
#if defined(__hpux) && defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 600)
  return 0;
#elif defined(__hpux) && defined(_XOPEN_SOURCE_EXTENDED)
  return 0;
#else
  force compilation error
#endif
}
    ]])
  ],[
    tst_lib_xnet_required="yes"
    LIBS="$LIBS -lxnet"
  ])
  AC_MSG_RESULT([$tst_lib_xnet_required])
])


dnl CURL_CHECK_AIX_ALL_SOURCE
dnl -------------------------------------------------
dnl Provides a replacement of traditional AC_AIX with
dnl an uniform behaviour across all autoconf versions,
dnl and with our own placement rules.

AC_DEFUN([CURL_CHECK_AIX_ALL_SOURCE], [
  AH_VERBATIM([_ALL_SOURCE],
    [/* Define to 1 if OS is AIX. */
#ifndef _ALL_SOURCE
#  undef _ALL_SOURCE
#endif])
  AC_BEFORE([$0], [AC_SYS_LARGEFILE])dnl
  AC_BEFORE([$0], [CURL_CONFIGURE_REENTRANT])dnl
  AC_MSG_CHECKING([if OS is AIX (to define _ALL_SOURCE)])
  AC_EGREP_CPP([yes_this_is_aix],[
#ifdef _AIX
   yes_this_is_aix
#endif
  ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE(_ALL_SOURCE)
  ],[
    AC_MSG_RESULT([no])
  ])
])


dnl CURL_CHECK_HEADER_WINDOWS
dnl -------------------------------------------------
dnl Check for compilable and valid windows.h header

AC_DEFUN([CURL_CHECK_HEADER_WINDOWS], [
  AC_CACHE_CHECK([for windows.h], [ac_cv_header_windows_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__)
        HAVE_WINDOWS_H shall not be defined.
#else
        int dummy=2*WINVER;
#endif
      ]])
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
        AC_LANG_PROGRAM([[
        ]],[[
#if defined(__MINGW32__) || defined(__MINGW32CE__) || \
   (defined(_MSC_VER) && (defined(_WIN32) || defined(_WIN64)))
          int dummy=1;
#else
          Not a native Windows build target.
#endif
        ]])
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


dnl CURL_CHECK_HEADER_WINSOCK
dnl -------------------------------------------------
dnl Check for compilable and valid winsock.h header

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock.h], [ac_cv_header_winsock_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__)
        HAVE_WINSOCK_H shall not be defined.
#else
        int dummy=WSACleanup();
#endif
      ]])
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
      AC_LANG_PROGRAM([[
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__) || defined(__MINGW32CE__)
        HAVE_WINSOCK2_H shall not be defined.
#else
        int dummy=2*IPPROTO_ESP;
#endif
      ]])
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
      AC_LANG_PROGRAM([[
#undef inline
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__) || defined(__MINGW32CE__)
        HAVE_WS2TCPIP_H shall not be defined.
#else
        int dummy=2*IP_PKTINFO;
#endif
      ]])
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
      AC_LANG_PROGRAM([[
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <winldap.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__)
        HAVE_WINLDAP_H shall not be defined.
#else
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        ULONG res = ldap_unbind(ldp);
#endif
      ]])
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
      AC_LANG_PROGRAM([[
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include <winldap.h>
#include <winber.h>
      ]],[[
#if defined(__CYGWIN__) || defined(__CEGCC__)
        HAVE_WINBER_H shall not be defined.
#else
        BERVAL *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
#endif
      ]])
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
      AC_LANG_PROGRAM([[
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
      ]],[[
        BerValue *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
      ]])
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
      AC_LANG_PROGRAM([[
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
      ]],[[
        BerValue *bvp = NULL;
        BerElement *bep = ber_init(bvp);
        ber_free(bep, 1);
      ]])
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
      AC_LANG_PROGRAM([[
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
      ]],[[
        LDAP *ldp = ldap_init("dummy", LDAP_PORT);
        int res = ldap_unbind(ldp);
      ]])
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
      AC_LANG_PROGRAM([[
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
      ]],[[
        LDAP *ldp = ldapssl_init("dummy", LDAPS_PORT, 1);
      ]])
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
      AC_LANG_PROGRAM([[
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
      ]],[[
        char *cert_label = NULL;
        LDAP *ldp = ldap_ssl_init("dummy", LDAPS_PORT, cert_label);
      ]])
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
  curl_cv_save_LIBS="$LIBS"
  curl_cv_ldap_LIBS="unknown"
  #
  for x_nlibs in '' "$u_libs" \
    '-lwldap32' ; do
    if test "$curl_cv_ldap_LIBS" = "unknown"; then
      if test -z "$x_nlibs"; then
        LIBS="$curl_cv_save_LIBS"
      else
        LIBS="$x_nlibs $curl_cv_save_LIBS"
      fi
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
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
        ]],[[
          BERVAL *bvp = NULL;
          BerElement *bep = ber_init(bvp);
          LDAP *ldp = ldap_init("dummy", LDAP_PORT);
          ULONG res = ldap_unbind(ldp);
          ber_free(bep, 1);
        ]])
      ],[
        curl_cv_ldap_LIBS="$x_nlibs"
      ])
    fi
  done
  #
  LIBS="$curl_cv_save_LIBS"
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
  curl_cv_save_LIBS="$LIBS"
  curl_cv_ldap_LIBS="unknown"
  #
  for x_nlibs in '' "$u_libs" \
    '-lldap' \
    '-llber -lldap' \
    '-lldap -llber' \
    '-lldapssl -lldapx -lldapsdk' \
    '-lldapsdk -lldapx -lldapssl' ; do
    if test "$curl_cv_ldap_LIBS" = "unknown"; then
      if test -z "$x_nlibs"; then
        LIBS="$curl_cv_save_LIBS"
      else
        LIBS="$x_nlibs $curl_cv_save_LIBS"
      fi
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
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
        ]],[[
          BerValue *bvp = NULL;
          BerElement *bep = ber_init(bvp);
          LDAP *ldp = ldap_init("dummy", LDAP_PORT);
          int res = ldap_unbind(ldp);
          ber_free(bep, 1);
        ]])
      ],[
        curl_cv_ldap_LIBS="$x_nlibs"
      ])
    fi
  done
  #
  LIBS="$curl_cv_save_LIBS"
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
      AC_LANG_PROGRAM([[
#include <malloc.h>
      ]],[[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ]])
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
      AC_LANG_PROGRAM([[
#include <stdlib.h>
      ]],[[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ]])
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


dnl CURL_CHECK_HEADER_MEMORY
dnl -------------------------------------------------
dnl Check for compilable and valid memory.h header,
dnl and check if it is needed even with stdlib.h for
dnl memory related functions.

AC_DEFUN([CURL_CHECK_HEADER_MEMORY], [
  AC_CACHE_CHECK([for memory.h], [ac_cv_header_memory_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <memory.h>
      ]],[[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ]])
    ],[
      ac_cv_header_memory_h="yes"
    ],[
      ac_cv_header_memory_h="no"
    ])
  ])
  if test "$ac_cv_header_memory_h" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_MEMORY_H, 1,
      [Define to 1 if you have the memory.h header file.])
    #
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <stdlib.h>
      ]],[[
        void *p = malloc(10);
        void *q = calloc(10,10);
        free(p);
        free(q);
      ]])
    ],[
      curl_cv_need_header_memory_h="no"
    ],[
      curl_cv_need_header_memory_h="yes"
    ])
    #
    case "$curl_cv_need_header_memory_h" in
      yes)
        AC_DEFINE_UNQUOTED(NEED_MEMORY_H, 1,
          [Define to 1 if you need the memory.h header file even with stdlib.h])
        ;;
    esac
  fi
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
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        getnameinfo();
      ]])
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
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
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
      ]],[[
        getnameinfo(0, 0, 0, 0, 0, 0, 0);
      ]])
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
              if test "$curl_cv_func_getnameinfo_args" = "unknown"; then
                AC_COMPILE_IFELSE([
                  AC_LANG_PROGRAM([[
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
                  ]],[[
                    $gni_arg2 salen=0;
                    $gni_arg46 hostlen=0;
                    $gni_arg46 servlen=0;
                    $gni_arg7 flags=0;
                    int res = getnameinfo(0, salen, 0, hostlen, 0, servlen, flags);
                  ]])
                ],[
                  curl_cv_func_getnameinfo_args="$gni_arg1,$gni_arg2,$gni_arg46,$gni_arg7"
                ])
              fi
            done
          done
        done
      done
    ]) # AC-CACHE-CHECK
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
])


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
      AC_LANG_PROGRAM([[
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
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
      ]],[[
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
      ]]) # AC-LANG-PROGRAM
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
        AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
        ]],[[
          unsigned int dummy= NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
        ]])
      ],[
        ac_cv_working_ni_withscopeid="yes"
      ],[
        ac_cv_working_ni_withscopeid="no"
      ]) # AC-COMPILE-IFELSE
    ]) # AC-RUN-IFELSE
  ]) # AC-CACHE-CHECK
  case "$ac_cv_working_ni_withscopeid" in
    yes)
      AC_DEFINE(HAVE_NI_WITHSCOPEID, 1,
        [Define to 1 if NI_WITHSCOPEID exists and works.])
      ;;
  esac
])


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
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
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
    ]],[[
      recv(0, 0, 0, 0);
    ]])
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
                if test "$curl_cv_func_recv_args" = "unknown"; then
                  AC_COMPILE_IFELSE([
                    AC_LANG_PROGRAM([[
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
                      extern $recv_retv RECVCALLCONV
                      recv($recv_arg1, $recv_arg2, $recv_arg3, $recv_arg4);
                    ]],[[
                      $recv_arg1 s=0;
                      $recv_arg2 buf=0;
                      $recv_arg3 len=0;
                      $recv_arg4 flags=0;
                      $recv_retv res = recv(s, buf, len, flags);
                    ]])
                  ],[
                    curl_cv_func_recv_args="$recv_arg1,$recv_arg2,$recv_arg3,$recv_arg4,$recv_retv"
                  ])
                fi
              done
            done
          done
        done
      done
    ]) # AC-CACHE-CHECK
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
])


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
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
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
    ]],[[
      send(0, 0, 0, 0);
    ]])
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
                if test "$curl_cv_func_send_args" = "unknown"; then
                  AC_COMPILE_IFELSE([
                    AC_LANG_PROGRAM([[
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
                      extern $send_retv SENDCALLCONV
                      send($send_arg1, $send_arg2, $send_arg3, $send_arg4);
                    ]],[[
                      $send_arg1 s=0;
                      $send_arg3 len=0;
                      $send_arg4 flags=0;
                      $send_retv res = send(s, 0, len, flags);
                    ]])
                  ],[
                    curl_cv_func_send_args="$send_arg1,$send_arg2,$send_arg3,$send_arg4,$send_retv"
                  ])
                fi
              done
            done
          done
        done
      done
    ]) # AC-CACHE-CHECK
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
])


dnl CURL_CHECK_FUNC_RECVFROM
dnl -------------------------------------------------
dnl Test if the socket recvfrom() function is available,
dnl and check its return type and the types of its
dnl arguments. If the function succeeds HAVE_RECVFROM
dnl will be defined, defining the types of the arguments
dnl in RECVFROM_TYPE_ARG1, RECVFROM_TYPE_ARG2, and so on
dnl to RECVFROM_TYPE_ARG6, defining also the type of the
dnl function return value in RECVFROM_TYPE_RETV.
dnl Notice that the types returned for pointer arguments
dnl will actually be the type pointed by the pointer.

AC_DEFUN([CURL_CHECK_FUNC_RECVFROM], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  #
  AC_MSG_CHECKING([for recvfrom])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
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
    ]],[[
      recvfrom(0, 0, 0, 0, 0, 0);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    curl_cv_recvfrom="yes"
  ],[
    AC_MSG_RESULT([no])
    curl_cv_recvfrom="no"
  ])
  #
  if test "$curl_cv_recvfrom" = "yes"; then
    AC_CACHE_CHECK([types of args and return type for recvfrom],
      [curl_cv_func_recvfrom_args], [
      curl_cv_func_recvfrom_args="unknown"
      for recvfrom_retv in 'int' 'ssize_t'; do
        for recvfrom_arg1 in 'int' 'ssize_t' 'SOCKET'; do
          for recvfrom_arg2 in 'char *' 'void *'; do
            for recvfrom_arg3 in 'size_t' 'int' 'socklen_t' 'unsigned int'; do
              for recvfrom_arg4 in 'int' 'unsigned int'; do
                for recvfrom_arg5 in 'struct sockaddr *' 'void *'; do
                  for recvfrom_arg6 in 'socklen_t *' 'int *' 'unsigned int *' 'size_t *' 'void *'; do
                    if test "$curl_cv_func_recvfrom_args" = "unknown"; then
                      AC_COMPILE_IFELSE([
                        AC_LANG_PROGRAM([[
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
#define RECVFROMCALLCONV PASCAL
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#define RECVFROMCALLCONV
#endif
                          extern $recvfrom_retv RECVFROMCALLCONV
                          recvfrom($recvfrom_arg1, $recvfrom_arg2,
                                   $recvfrom_arg3, $recvfrom_arg4,
                                   $recvfrom_arg5, $recvfrom_arg6);
                        ]],[[
                          $recvfrom_arg1 s=0;
                          $recvfrom_arg2 buf=0;
                          $recvfrom_arg3 len=0;
                          $recvfrom_arg4 flags=0;
                          $recvfrom_arg5 addr=0;
                          $recvfrom_arg6 addrlen=0;
                          $recvfrom_retv res=0;
                          res = recvfrom(s, buf, len, flags, addr, addrlen);
                        ]])
                      ],[
                        curl_cv_func_recvfrom_args="$recvfrom_arg1,$recvfrom_arg2,$recvfrom_arg3,$recvfrom_arg4,$recvfrom_arg5,$recvfrom_arg6,$recvfrom_retv"
                      ])
                    fi
                  done
                done
              done
            done
          done
        done
      done
    ]) # AC-CACHE-CHECK
    # Nearly last minute change for this release starts here
    AC_DEFINE_UNQUOTED(HAVE_RECVFROM, 1,
      [Define to 1 if you have the recvfrom function.])
    ac_cv_func_recvfrom="yes"
    # Nearly last minute change for this release ends here
    if test "$curl_cv_func_recvfrom_args" = "unknown"; then
      AC_MSG_WARN([Cannot find proper types to use for recvfrom args])
    else
      recvfrom_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_recvfrom_args" | sed 's/\*/\*/g'`
      IFS=$recvfrom_prev_IFS
      shift
      #
      recvfrom_ptrt_arg2=$[2]
      recvfrom_ptrt_arg5=$[5]
      recvfrom_ptrt_arg6=$[6]
      #
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG1, $[1],
        [Define to the type of arg 1 for recvfrom.])
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG3, $[3],
        [Define to the type of arg 3 for recvfrom.])
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG4, $[4],
        [Define to the type of arg 4 for recvfrom.])
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_RETV, $[7],
        [Define to the function return type for recvfrom.])
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
      recvfrom_type_arg2=`echo $recvfrom_ptrt_arg2 | sed 's/ \*//'`
      recvfrom_type_arg5=`echo $recvfrom_ptrt_arg5 | sed 's/ \*//'`
      recvfrom_type_arg6=`echo $recvfrom_ptrt_arg6 | sed 's/ \*//'`
      #
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG2, $recvfrom_type_arg2,
        [Define to the type pointed by arg 2 for recvfrom.])
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG5, $recvfrom_type_arg5,
        [Define to the type pointed by arg 5 for recvfrom.])
      AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG6, $recvfrom_type_arg6,
        [Define to the type pointed by arg 6 for recvfrom.])
      #
      if test "$recvfrom_type_arg2" = "void"; then
        AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG2_IS_VOID, 1,
          [Define to 1 if the type pointed by arg 2 for recvfrom is void.])
      fi
      if test "$recvfrom_type_arg5" = "void"; then
        AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG5_IS_VOID, 1,
          [Define to 1 if the type pointed by arg 5 for recvfrom is void.])
      fi
      if test "$recvfrom_type_arg6" = "void"; then
        AC_DEFINE_UNQUOTED(RECVFROM_TYPE_ARG6_IS_VOID, 1,
          [Define to 1 if the type pointed by arg 6 for recvfrom is void.])
      fi
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set +f
          ;;
      esac
      #
      AC_DEFINE_UNQUOTED(HAVE_RECVFROM, 1,
        [Define to 1 if you have the recvfrom function.])
      ac_cv_func_recvfrom="yes"
    fi
  else
    AC_MSG_WARN([Unable to link function recvfrom])
  fi
])


dnl CURL_CHECK_MSG_NOSIGNAL
dnl -------------------------------------------------
dnl Check for MSG_NOSIGNAL

AC_DEFUN([CURL_CHECK_MSG_NOSIGNAL], [
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  AC_CACHE_CHECK([for MSG_NOSIGNAL], [ac_cv_msg_nosignal], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
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
      ]],[[
        int flag=MSG_NOSIGNAL;
      ]])
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
])


dnl CURL_CHECK_STRUCT_TIMEVAL
dnl -------------------------------------------------
dnl Check for timeval struct

AC_DEFUN([CURL_CHECK_STRUCT_TIMEVAL], [
  AC_REQUIRE([AC_HEADER_TIME])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK])dnl
  AC_REQUIRE([CURL_CHECK_HEADER_WINSOCK2])dnl
  AC_CHECK_HEADERS(sys/types.h sys/time.h time.h sys/socket.h)
  AC_CACHE_CHECK([for struct timeval], [ac_cv_struct_timeval], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
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
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
      ]],[[
        struct timeval ts;
        ts.tv_sec  = 0;
        ts.tv_usec = 0;
      ]])
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
])


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
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
        ]],[[
          static volatile sig_atomic_t dummy = 0;
        ]])
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
])


dnl TYPE_IN_ADDR_T
dnl -------------------------------------------------
dnl Check for in_addr_t: it is used to receive the return code of inet_addr()
dnl and a few other things.

AC_DEFUN([TYPE_IN_ADDR_T], [
  AC_CHECK_TYPE([in_addr_t], ,[
    dnl in_addr_t not available
    AC_CACHE_CHECK([for in_addr_t equivalent],
      [curl_cv_in_addr_t_equiv], [
      curl_cv_in_addr_t_equiv="unknown"
      for t in "unsigned long" int size_t unsigned long; do
        if test "$curl_cv_in_addr_t_equiv" = "unknown"; then
          AC_LINK_IFELSE([
            AC_LANG_PROGRAM([[
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
            ]],[[
              $t data = inet_addr ("1.2.3.4");
            ]])
          ],[
            curl_cv_in_addr_t_equiv="$t"
          ])
        fi
      done
    ])
    case "$curl_cv_in_addr_t_equiv" in
      unknown)
        AC_MSG_ERROR([Cannot find a type to use in place of in_addr_t])
        ;;
      *)
        AC_DEFINE_UNQUOTED(in_addr_t, $curl_cv_in_addr_t_equiv,
          [Type to use in place of in_addr_t when system does not provide it.])
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
  ])
])


dnl CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC
dnl -------------------------------------------------
dnl Check if monotonic clock_gettime is available.

AC_DEFUN([CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC], [
  AC_REQUIRE([AC_HEADER_TIME])dnl
  AC_CHECK_HEADERS(sys/types.h sys/time.h time.h)
  AC_MSG_CHECKING([for monotonic clock_gettime])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
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
    ]],[[
      struct timespec ts;
      (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    ac_cv_func_clock_gettime="yes"
  ],[
    AC_MSG_RESULT([no])
    ac_cv_func_clock_gettime="no"
  ])
  dnl Definition of HAVE_CLOCK_GETTIME_MONOTONIC is intentionally postponed
  dnl until library linking and run-time checks for clock_gettime succeed.
])


dnl CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC
dnl -------------------------------------------------
dnl If monotonic clock_gettime is available then,
dnl check and prepended to LIBS any needed libraries.

AC_DEFUN([CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC], [
  AC_REQUIRE([CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC])dnl
  #
  if test "$ac_cv_func_clock_gettime" = "yes"; then
    #
    AC_MSG_CHECKING([for clock_gettime in libraries])
    #
    curl_cv_save_LIBS="$LIBS"
    curl_cv_gclk_LIBS="unknown"
    #
    for x_xlibs in '' '-lrt' '-lposix4' ; do
      if test "$curl_cv_gclk_LIBS" = "unknown"; then
        if test -z "$x_xlibs"; then
          LIBS="$curl_cv_save_LIBS"
        else
          LIBS="$x_xlibs $curl_cv_save_LIBS"
        fi
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM([[
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
          ]],[[
            struct timespec ts;
            (void)clock_gettime(CLOCK_MONOTONIC, &ts);
          ]])
        ],[
          curl_cv_gclk_LIBS="$x_xlibs"
        ])
      fi
    done
    #
    LIBS="$curl_cv_save_LIBS"
    #
    case X-"$curl_cv_gclk_LIBS" in
      X-unknown)
        AC_MSG_RESULT([cannot find clock_gettime])
        AC_MSG_WARN([HAVE_CLOCK_GETTIME_MONOTONIC will not be defined])
        ac_cv_func_clock_gettime="no"
        ;;
      X-)
        AC_MSG_RESULT([no additional lib required])
        ac_cv_func_clock_gettime="yes"
        ;;
      *)
        if test -z "$curl_cv_save_LIBS"; then
          LIBS="$curl_cv_gclk_LIBS"
        else
          LIBS="$curl_cv_gclk_LIBS $curl_cv_save_LIBS"
        fi
        CURL_LIBS="$CURL_LIBS $curl_cv_gclk_LIBS"
        AC_MSG_RESULT([$curl_cv_gclk_LIBS])
        ac_cv_func_clock_gettime="yes"
        ;;
    esac
    #
    dnl only do runtime verification when not cross-compiling
    if test "x$cross_compiling" != "xyes" &&
      test "$ac_cv_func_clock_gettime" = "yes"; then
      AC_MSG_CHECKING([if monotonic clock_gettime works])
      AC_RUN_IFELSE([
        AC_LANG_PROGRAM([[
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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
        ]],[[
          struct timespec ts;
          if (0 == clock_gettime(CLOCK_MONOTONIC, &ts))
            exit(0);
          else
            exit(1);
        ]])
      ],[
        AC_MSG_RESULT([yes])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([HAVE_CLOCK_GETTIME_MONOTONIC will not be defined])
        ac_cv_func_clock_gettime="no"
        LIBS="$curl_cv_save_LIBS"
      ])
    fi
    #
    case "$ac_cv_func_clock_gettime" in
      yes)
        AC_DEFINE_UNQUOTED(HAVE_CLOCK_GETTIME_MONOTONIC, 1,
          [Define to 1 if you have the clock_gettime function and monotonic timer.])
        ;;
    esac
    #
  fi
  #
])


dnl CURL_CHECK_LIBS_CONNECT
dnl -------------------------------------------------
dnl Verify if network connect function is already available
dnl using current libraries or if another one is required.

AC_DEFUN([CURL_CHECK_LIBS_CONNECT], [
  AC_REQUIRE([CURL_INCLUDES_WINSOCK2])dnl
  AC_MSG_CHECKING([for connect in libraries])
  tst_connect_save_LIBS="$LIBS"
  tst_connect_need_LIBS="unknown"
  for tst_lib in '' '-lsocket' ; do
    if test "$tst_connect_need_LIBS" = "unknown"; then
      LIBS="$tst_lib $tst_connect_save_LIBS"
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_winsock2
          #ifndef HAVE_WINDOWS_H
            int connect(int, void*, int);
          #endif
        ]],[[
          if(0 != connect(0, 0, 0))
            return 1;
        ]])
      ],[
        tst_connect_need_LIBS="$tst_lib"
      ])
    fi
  done
  LIBS="$tst_connect_save_LIBS"
  #
  case X-"$tst_connect_need_LIBS" in
    X-unknown)
      AC_MSG_RESULT([cannot find connect])
      AC_MSG_ERROR([cannot find connect function in libraries.])
      ;;
    X-)
      AC_MSG_RESULT([yes])
      ;;
    *)
      AC_MSG_RESULT([$tst_connect_need_LIBS])
      LIBS="$tst_connect_need_LIBS $tst_connect_save_LIBS"
      ;;
  esac
])


dnl CURL_DEFINE_UNQUOTED (VARIABLE, [VALUE])
dnl -------------------------------------------------
dnl Like AC_DEFINE_UNQUOTED this macro will define a C preprocessor
dnl symbol that can be further used in custom template configuration
dnl files. This macro, unlike AC_DEFINE_UNQUOTED, does not use a third
dnl argument for the description. Symbol definitions done with this
dnl macro are intended to be exclusively used in handcrafted *.h.in
dnl template files. Contrary to what AC_DEFINE_UNQUOTED does, this one
dnl prevents autoheader generation and insertion of symbol template
dnl stub and definition into the first configuration header file. Do
dnl not use this macro as a replacement for AC_DEFINE_UNQUOTED, each
dnl one serves different functional needs.

AC_DEFUN([CURL_DEFINE_UNQUOTED], [
cat >>confdefs.h <<_EOF
[@%:@define] $1 ifelse($#, 2, [$2], 1)
_EOF
])


dnl CURL_CONFIGURE_LONG
dnl -------------------------------------------------
dnl Find out the size of long as reported by sizeof() and define
dnl CURL_SIZEOF_LONG as appropriate to be used in template file
dnl include/curl/curlbuild.h.in to properly configure the library.
dnl The size of long is a build time characteristic and as such
dnl must be recorded in curlbuild.h

AC_DEFUN([CURL_CONFIGURE_LONG], [
  if test -z "$ac_cv_sizeof_long" ||
    test "$ac_cv_sizeof_long" -eq "0"; then
    AC_MSG_ERROR([cannot find out size of long.])
  fi
  CURL_DEFINE_UNQUOTED([CURL_SIZEOF_LONG], [$ac_cv_sizeof_long])
])


dnl CURL_CONFIGURE_CURL_SOCKLEN_T
dnl -------------------------------------------------
dnl Find out suitable curl_socklen_t data type definition and size, making
dnl appropriate definitions for template file include/curl/curlbuild.h.in
dnl to properly configure and use the library.
dnl
dnl The need for the curl_socklen_t definition arises mainly to properly
dnl interface HP-UX systems which on one hand have a typedef'ed socklen_t
dnl data type which is 32 or 64-Bit wide depending on the data model being
dnl used, and that on the other hand is only actually used when interfacing
dnl the X/Open sockets provided in the xnet library.

AC_DEFUN([CURL_CONFIGURE_CURL_SOCKLEN_T], [
  AC_REQUIRE([CURL_INCLUDES_WS2TCPIP])dnl
  AC_REQUIRE([CURL_INCLUDES_SYS_SOCKET])dnl
  AC_REQUIRE([CURL_PREPROCESS_CALLCONV])dnl
  #
  AC_MSG_CHECKING([for curl_socklen_t data type])
  curl_typeof_curl_socklen_t="unknown"
  for arg1 in int SOCKET; do
    for arg2 in 'struct sockaddr' void; do
      for t in socklen_t int size_t 'unsigned int' long 'unsigned long' void; do
        if test "$curl_typeof_curl_socklen_t" = "unknown"; then
          AC_COMPILE_IFELSE([
            AC_LANG_PROGRAM([[
              $curl_includes_ws2tcpip
              $curl_includes_sys_socket
              $curl_preprocess_callconv
              extern int FUNCALLCONV getpeername($arg1, $arg2 *, $t *);
            ]],[[
              $t *lenptr = 0;
              if(0 != getpeername(0, 0, lenptr))
                return 1;
            ]])
          ],[
            curl_typeof_curl_socklen_t="$t"
          ])
        fi
      done
    done
  done
  for t in socklen_t int; do
    if test "$curl_typeof_curl_socklen_t" = "void"; then
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_sys_socket
          typedef $t curl_socklen_t;
        ]],[[
          curl_socklen_t dummy;
        ]])
      ],[
        curl_typeof_curl_socklen_t="$t"
      ])
    fi
  done
  AC_MSG_RESULT([$curl_typeof_curl_socklen_t])
  if test "$curl_typeof_curl_socklen_t" = "void" ||
    test "$curl_typeof_curl_socklen_t" = "unknown"; then
    AC_MSG_ERROR([cannot find data type for curl_socklen_t.])
  fi
  #
  AC_MSG_CHECKING([size of curl_socklen_t])
  curl_sizeof_curl_socklen_t="unknown"
  curl_pull_headers_socklen_t="unknown"
  if test "$ac_cv_header_ws2tcpip_h" = "yes"; then
    tst_pull_header_checks='none ws2tcpip'
    tst_size_checks='4'
  else
    tst_pull_header_checks='none systypes syssocket'
    tst_size_checks='4 8 2'
  fi
  for tst_size in $tst_size_checks; do
    for tst_pull_headers in $tst_pull_header_checks; do
      if test "$curl_sizeof_curl_socklen_t" = "unknown"; then
        case $tst_pull_headers in
          ws2tcpip)
            tmp_includes="$curl_includes_ws2tcpip"
            ;;
          systypes)
            tmp_includes="$curl_includes_sys_types"
            ;;
          syssocket)
            tmp_includes="$curl_includes_sys_socket"
            ;;
          *)
            tmp_includes=""
            ;;
        esac
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
            $tmp_includes
            typedef $curl_typeof_curl_socklen_t curl_socklen_t;
            typedef char dummy_arr[sizeof(curl_socklen_t) == $tst_size ? 1 : -1];
          ]],[[
            curl_socklen_t dummy;
          ]])
        ],[
          curl_sizeof_curl_socklen_t="$tst_size"
          curl_pull_headers_socklen_t="$tst_pull_headers"
        ])
      fi
    done
  done
  AC_MSG_RESULT([$curl_sizeof_curl_socklen_t])
  if test "$curl_sizeof_curl_socklen_t" = "unknown"; then
    AC_MSG_ERROR([cannot find out size of curl_socklen_t.])
  fi
  #
  case $curl_pull_headers_socklen_t in
    ws2tcpip)
      CURL_DEFINE_UNQUOTED([CURL_PULL_WS2TCPIP_H])
      ;;
    systypes)
      CURL_DEFINE_UNQUOTED([CURL_PULL_SYS_TYPES_H])
      ;;
    syssocket)
      CURL_DEFINE_UNQUOTED([CURL_PULL_SYS_TYPES_H])
      CURL_DEFINE_UNQUOTED([CURL_PULL_SYS_SOCKET_H])
      ;;
  esac
  CURL_DEFINE_UNQUOTED([CURL_TYPEOF_CURL_SOCKLEN_T], [$curl_typeof_curl_socklen_t])
  CURL_DEFINE_UNQUOTED([CURL_SIZEOF_CURL_SOCKLEN_T], [$curl_sizeof_curl_socklen_t])
])


dnl CURL_CHECK_FUNC_SELECT
dnl -------------------------------------------------
dnl Test if the socket select() function is available,
dnl and check its return type and the types of its
dnl arguments. If the function succeeds HAVE_SELECT
dnl will be defined, defining the types of the
dnl arguments in SELECT_TYPE_ARG1, SELECT_TYPE_ARG234
dnl and SELECT_TYPE_ARG5, defining the type of the
dnl function return value in SELECT_TYPE_RETV, and
dnl also defining the type qualifier of fifth argument
dnl in SELECT_QUAL_ARG5.

AC_DEFUN([CURL_CHECK_FUNC_SELECT], [
  AC_REQUIRE([CURL_CHECK_STRUCT_TIMEVAL])dnl
  AC_CHECK_HEADERS(sys/select.h sys/socket.h)
  #
  AC_MSG_CHECKING([for select])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
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
#ifndef HAVE_WINDOWS_H
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif
    ]],[[
      select(0, 0, 0, 0, 0);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    curl_cv_select="yes"
  ],[
    AC_MSG_RESULT([no])
    curl_cv_select="no"
  ])
  #
  if test "$curl_cv_select" = "yes"; then
    AC_CACHE_CHECK([types of args and return type for select],
      [curl_cv_func_select_args], [
      curl_cv_func_select_args="unknown"
      for sel_retv in 'int' 'ssize_t'; do
        for sel_arg1 in 'int' 'ssize_t' 'size_t' 'unsigned long int' 'unsigned int'; do
          for sel_arg234 in 'fd_set *' 'int *' 'void *'; do
            for sel_arg5 in 'struct timeval *' 'const struct timeval *'; do
              if test "$curl_cv_func_select_args" = "unknown"; then
                AC_COMPILE_IFELSE([
                  AC_LANG_PROGRAM([[
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
#define SELECTCALLCONV PASCAL
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
#ifndef HAVE_WINDOWS_H
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#define SELECTCALLCONV
#endif
#ifndef HAVE_STRUCT_TIMEVAL
                    struct timeval {
                      long tv_sec;
                      long tv_usec;
                    };
#endif
                    extern $sel_retv SELECTCALLCONV select($sel_arg1,
                                                           $sel_arg234,
                                                           $sel_arg234,
                                                           $sel_arg234,
                                                           $sel_arg5);
                  ]],[[
                    $sel_arg1   nfds=0;
                    $sel_arg234 rfds=0;
                    $sel_arg234 wfds=0;
                    $sel_arg234 efds=0;
                    $sel_retv res = select(nfds, rfds, wfds, efds, 0);
                  ]])
                ],[
                  curl_cv_func_select_args="$sel_arg1,$sel_arg234,$sel_arg5,$sel_retv"
                ])
              fi
            done
          done
        done
      done
    ]) # AC-CACHE-CHECK
    if test "$curl_cv_func_select_args" = "unknown"; then
      AC_MSG_WARN([Cannot find proper types to use for select args])
      AC_MSG_WARN([HAVE_SELECT will not be defined])
    else
      select_prev_IFS=$IFS; IFS=','
      set dummy `echo "$curl_cv_func_select_args" | sed 's/\*/\*/g'`
      IFS=$select_prev_IFS
      shift
      #
      sel_qual_type_arg5=$[3]
      #
      AC_DEFINE_UNQUOTED(SELECT_TYPE_ARG1, $[1],
        [Define to the type of arg 1 for select.])
      AC_DEFINE_UNQUOTED(SELECT_TYPE_ARG234, $[2],
        [Define to the type of args 2, 3 and 4 for select.])
      AC_DEFINE_UNQUOTED(SELECT_TYPE_RETV, $[4],
        [Define to the function return type for select.])
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
      case "$sel_qual_type_arg5" in
        const*)
          sel_qual_arg5=const
          sel_type_arg5=`echo $sel_qual_type_arg5 | sed 's/^const //'`
        ;;
        *)
          sel_qual_arg5=
          sel_type_arg5=$sel_qual_type_arg5
        ;;
      esac
      #
      AC_DEFINE_UNQUOTED(SELECT_QUAL_ARG5, $sel_qual_arg5,
        [Define to the type qualifier of arg 5 for select.])
      AC_DEFINE_UNQUOTED(SELECT_TYPE_ARG5, $sel_type_arg5,
        [Define to the type of arg 5 for select.])
      #
      case $prev_sh_opts in
        *f*)
          ;;
        *)
          set +f
          ;;
      esac
      #
      AC_DEFINE_UNQUOTED(HAVE_SELECT, 1,
        [Define to 1 if you have the select function.])
      ac_cv_func_select="yes"
    fi
  fi
])


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
      AC_LANG_PROGRAM([[
#define c99_vmacro3(first, ...) fun3(first, __VA_ARGS__)
#define c99_vmacro2(first, ...) fun2(first, __VA_ARGS__)
        int fun3(int arg1, int arg2, int arg3);
        int fun2(int arg1, int arg2);
        int fun3(int arg1, int arg2, int arg3)
        { return arg1 + arg2 + arg3; }
        int fun2(int arg1, int arg2)
        { return arg1 + arg2; }
      ]],[[
        int res3 = c99_vmacro3(1, 2, 3);
        int res2 = c99_vmacro2(1, 2);
      ]])
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
      AC_LANG_PROGRAM([[
#define gcc_vmacro3(first, args...) fun3(first, args)
#define gcc_vmacro2(first, args...) fun2(first, args)
        int fun3(int arg1, int arg2, int arg3);
        int fun2(int arg1, int arg2);
        int fun3(int arg1, int arg2, int arg3)
        { return arg1 + arg2 + arg3; }
        int fun2(int arg1, int arg2)
        { return arg1 + arg2; }
      ]],[[
        int res3 = gcc_vmacro3(1, 2, 3);
        int res2 = gcc_vmacro2(1, 2);
      ]])
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


dnl CURL_CHECK_CA_BUNDLE
dnl -------------------------------------------------
dnl Check if a default ca-bundle should be used
dnl
dnl regarding the paths this will scan:
dnl /etc/ssl/certs/ca-certificates.crt Debian systems
dnl /etc/pki/tls/certs/ca-bundle.crt Redhat and Mandriva
dnl /usr/share/ssl/certs/ca-bundle.crt old(er) Redhat
dnl /usr/local/share/certs/ca-root.crt FreeBSD
dnl /etc/ssl/cert.pem OpenBSD
dnl /etc/ssl/certs/ (ca path) SUSE

AC_DEFUN([CURL_CHECK_CA_BUNDLE], [

  AC_MSG_CHECKING([default CA cert bundle/path])

  AC_ARG_WITH(ca-bundle,
AC_HELP_STRING([--with-ca-bundle=FILE], [File name to use as CA bundle])
AC_HELP_STRING([--without-ca-bundle], [Don't use a default CA bundle]),
  [
    want_ca="$withval"
    if test "x$want_ca" = "xyes"; then
      AC_MSG_ERROR([--with-ca-bundle=FILE requires a path to the CA bundle])
    fi
  ],
  [ want_ca="unset" ])
  AC_ARG_WITH(ca-path,
AC_HELP_STRING([--with-ca-path=DIRECTORY], [Directory to use as CA path])
AC_HELP_STRING([--without-ca-path], [Don't use a default CA path]),
  [
    want_capath="$withval"
    if test "x$want_capath" = "xyes"; then
      AC_MSG_ERROR([--with-ca-path=DIRECTORY requires a path to the CA path directory])
    fi
  ],
  [ want_capath="unset"])

  if test "x$want_ca" != "xno" -a "x$want_ca" != "xunset" -a \
          "x$want_capath" != "xno" -a "x$want_capath" != "xunset"; then
    dnl both given
    AC_MSG_ERROR([Can't specify both --with-ca-bundle and --with-ca-path.])
  elif test "x$want_ca" != "xno" -a "x$want_ca" != "xunset"; then
    dnl --with-ca-bundle given
    ca="$want_ca"
    capath="no"
  elif test "x$want_capath" != "xno" -a "x$want_capath" != "xunset"; then
    dnl --with-ca-path given
    if test "x$OPENSSL_ENABLED" != "x1"; then
      AC_MSG_ERROR([--with-ca-path only works with openSSL])
    fi
    capath="$want_capath"
    ca="no"
  else
    dnl neither of --with-ca-* given
    dnl first try autodetecting a CA bundle , then a CA path
    dnl both autodetections can be skipped by --without-ca-*
    ca="no"
    capath="no"
    if test "x$want_ca" = "xunset"; then
      dnl the path we previously would have installed the curl ca bundle
      dnl to, and thus we now check for an already existing cert in that place
      dnl in case we find no other
      if test "x$prefix" != xNONE; then
        cac="${prefix}/share/curl/curl-ca-bundle.crt"
      else
        cac="$ac_default_prefix/share/curl/curl-ca-bundle.crt"
      fi

      for a in /etc/ssl/certs/ca-certificates.crt \
               /etc/pki/tls/certs/ca-bundle.crt \
               /usr/share/ssl/certs/ca-bundle.crt \
               /usr/local/share/certs/ca-root.crt \
               /etc/ssl/cert.pem \
               "$cac"; do
        if test -f "$a"; then
          ca="$a"
          break
        fi
      done
    fi
    if test "x$want_capath" = "xunset" -a "x$ca" = "xno" -a \
            "x$OPENSSL_ENABLED" = "x1"; then
      for a in /etc/ssl/certs/; do
        if test -d "$a" && ls "$a"/[[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]].0 >/dev/null 2>/dev/null; then
          capath="$a"
          break
        fi
      done
    fi
  fi



  if test "x$ca" != "xno"; then
    CURL_CA_BUNDLE='"'$ca'"'
    AC_DEFINE_UNQUOTED(CURL_CA_BUNDLE, "$ca", [Location of default ca bundle])
    AC_SUBST(CURL_CA_BUNDLE)
    AC_MSG_RESULT([$ca])
  elif test "x$capath" != "xno"; then
    CURL_CA_PATH="\"$capath\""
    AC_DEFINE_UNQUOTED(CURL_CA_PATH, "$capath", [Location of default ca path])
    AC_MSG_RESULT([$capath (capath)])
  else
    AC_MSG_RESULT([no])
  fi
])


dnl DO_CURL_OFF_T_CHECK (TYPE, SIZE)
dnl -------------------------------------------------
dnl Internal macro for CURL_CONFIGURE_CURL_OFF_T

AC_DEFUN([DO_CURL_OFF_T_CHECK], [
  AC_REQUIRE([CURL_INCLUDES_INTTYPES])dnl
  if test "$curl_typeof_curl_off_t" = "unknown" && test ! -z "$1"; then
    tmp_includes=""
    tmp_source=""
    tmp_fmt=""
    case AS_TR_SH([$1]) in
      int64_t)
        tmp_includes="$curl_includes_inttypes"
        tmp_source="char f@<:@@:>@ = PRId64;"
        tmp_fmt="PRId64"
        ;;
      int32_t)
        tmp_includes="$curl_includes_inttypes"
        tmp_source="char f@<:@@:>@ = PRId32;"
        tmp_fmt="PRId32"
        ;;
      int16_t)
        tmp_includes="$curl_includes_inttypes"
        tmp_source="char f@<:@@:>@ = PRId16;"
        tmp_fmt="PRId16"
        ;;
    esac
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $tmp_includes
        typedef $1 curl_off_t;
        typedef char dummy_arr[sizeof(curl_off_t) == $2 ? 1 : -1];
      ]],[[
        $tmp_source
        curl_off_t dummy;
      ]])
    ],[
      if test -z "$tmp_fmt"; then
        curl_typeof_curl_off_t="$1"
        curl_sizeof_curl_off_t="$2"
      else
        CURL_CHECK_DEF([$tmp_fmt], [$curl_includes_inttypes], [silent])
        AS_VAR_PUSHDEF([tmp_HaveFmtDef], [curl_cv_have_def_$tmp_fmt])dnl
        AS_VAR_PUSHDEF([tmp_FmtDef], [curl_cv_def_$tmp_fmt])dnl
        if test AS_VAR_GET(tmp_HaveFmtDef) = "yes"; then
          curl_format_curl_off_t=AS_VAR_GET(tmp_FmtDef)
          curl_typeof_curl_off_t="$1"
          curl_sizeof_curl_off_t="$2"
        fi
        AS_VAR_POPDEF([tmp_FmtDef])dnl
        AS_VAR_POPDEF([tmp_HaveFmtDef])dnl
      fi
    ])
  fi
])


dnl DO_CURL_OFF_T_SUFFIX_CHECK (TYPE)
dnl -------------------------------------------------
dnl Internal macro for CURL_CONFIGURE_CURL_OFF_T

AC_DEFUN([DO_CURL_OFF_T_SUFFIX_CHECK], [
  AC_REQUIRE([CURL_INCLUDES_INTTYPES])dnl
  AC_MSG_CHECKING([constant suffix string for curl_off_t])
  #
  curl_suffix_curl_off_t="unknown"
  curl_suffix_curl_off_tu="unknown"
  #
  case AS_TR_SH([$1]) in
    long_long | __longlong | __longlong_t)
      tst_suffixes="LL::"
      ;;
    long)
      tst_suffixes="L::"
      ;;
    int)
      tst_suffixes="::"
      ;;
    __int64 | int64_t)
      tst_suffixes="LL:i64::"
      ;;
    __int32 | int32_t)
      tst_suffixes="L:i32::"
      ;;
    __int16 | int16_t)
      tst_suffixes="L:i16::"
      ;;
    *)
      AC_MSG_ERROR([unexpected data type $1])
      ;;
  esac
  #
  old_IFS=$IFS; IFS=':'
  for tmp_ssuf in $tst_suffixes ; do
    IFS=$old_IFS
    if test "x$curl_suffix_curl_off_t" = "xunknown"; then
      case $tmp_ssuf in
        i64 | i32 | i16)
          tmp_usuf="u$tmp_ssuf"
          ;;
        LL | L)
          tmp_usuf="U$tmp_ssuf"
          ;;
        *)
          tmp_usuf=""
          ;;
      esac
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_inttypes
          typedef $1 new_t;
        ]],[[
          new_t s1;
          new_t s2;
          s1 = -10$tmp_ssuf ;
          s2 =  20$tmp_ssuf ;
          if(s1 > s2)
            return 1;
        ]])
      ],[
        curl_suffix_curl_off_t="$tmp_ssuf"
        curl_suffix_curl_off_tu="$tmp_usuf"
      ])
    fi
  done
  IFS=$old_IFS
  #
  if test "x$curl_suffix_curl_off_t" = "xunknown"; then
    AC_MSG_ERROR([cannot find constant suffix string for curl_off_t.])
  else
    AC_MSG_RESULT([$curl_suffix_curl_off_t])
    AC_MSG_CHECKING([constant suffix string for unsigned curl_off_t])
    AC_MSG_RESULT([$curl_suffix_curl_off_tu])
  fi
  #
])


dnl CURL_CONFIGURE_CURL_OFF_T
dnl -------------------------------------------------
dnl Find out suitable curl_off_t data type definition and associated
dnl items, and make the appropriate definitions used in template file
dnl include/curl/curlbuild.h.in to properly configure the library.

AC_DEFUN([CURL_CONFIGURE_CURL_OFF_T], [
  AC_REQUIRE([CURL_INCLUDES_INTTYPES])dnl
  #
  AC_BEFORE([$0],[AC_SYS_LARGEFILE])dnl
  AC_BEFORE([$0],[CURL_CONFIGURE_REENTRANT])dnl
  AC_BEFORE([$0],[CURL_CHECK_AIX_ALL_SOURCE])dnl
  #
  if test -z "$SED"; then
    AC_MSG_ERROR([SED not set. Cannot continue without SED being set.])
  fi
  #
  AC_CHECK_SIZEOF(long)
  AC_CHECK_SIZEOF(void*)
  #
  if test -z "$ac_cv_sizeof_long" ||
    test "$ac_cv_sizeof_long" -eq "0"; then
    AC_MSG_ERROR([cannot find out size of long.])
  fi
  if test -z "$ac_cv_sizeof_voidp" ||
     test "$ac_cv_sizeof_voidp" -eq "0"; then
    AC_MSG_ERROR([cannot find out size of void*.])
  fi
  #
  x_LP64_long=""
  x_LP32_long=""
  x_LP16_long=""
  #
  if test "$ac_cv_sizeof_long" -eq "8" &&
     test "$ac_cv_sizeof_voidp" -ge "8"; then
    x_LP64_long="long"
  elif test "$ac_cv_sizeof_long" -eq "4" &&
       test "$ac_cv_sizeof_voidp" -ge "4"; then
    x_LP32_long="long"
  elif test "$ac_cv_sizeof_long" -eq "2" &&
       test "$ac_cv_sizeof_voidp" -ge "2"; then
    x_LP16_long="long"
  fi
  #
  dnl DO_CURL_OFF_T_CHECK results are stored in next 3 vars
  #
  curl_typeof_curl_off_t="unknown"
  curl_sizeof_curl_off_t="unknown"
  curl_format_curl_off_t="unknown"
  curl_format_curl_off_tu="unknown"
  #
  if test "$curl_typeof_curl_off_t" = "unknown"; then
    AC_MSG_CHECKING([for 64-bit curl_off_t data type])
    for t8 in          \
      "$x_LP64_long"   \
      'int64_t'        \
      '__int64'        \
      'long long'      \
      '__longlong'     \
      '__longlong_t'   ; do
      DO_CURL_OFF_T_CHECK([$t8], [8])
    done
    AC_MSG_RESULT([$curl_typeof_curl_off_t])
  fi
  if test "$curl_typeof_curl_off_t" = "unknown"; then
    AC_MSG_CHECKING([for 32-bit curl_off_t data type])
    for t4 in          \
      "$x_LP32_long"   \
      'int32_t'        \
      '__int32'        \
      'int'            ; do
      DO_CURL_OFF_T_CHECK([$t4], [4])
    done
    AC_MSG_RESULT([$curl_typeof_curl_off_t])
  fi
  if test "$curl_typeof_curl_off_t" = "unknown"; then
    AC_MSG_CHECKING([for 16-bit curl_off_t data type])
    for t2 in          \
      "$x_LP16_long"   \
      'int16_t'        \
      '__int16'        \
      'int'            ; do
      DO_CURL_OFF_T_CHECK([$t2], [2])
    done
    AC_MSG_RESULT([$curl_typeof_curl_off_t])
  fi
  if test "$curl_typeof_curl_off_t" = "unknown"; then
    AC_MSG_ERROR([cannot find data type for curl_off_t.])
  fi
  #
  AC_MSG_CHECKING([size of curl_off_t])
  AC_MSG_RESULT([$curl_sizeof_curl_off_t])
  #
  AC_MSG_CHECKING([formatting string directive for curl_off_t])
  if test "$curl_format_curl_off_t" != "unknown"; then
    x_pull_headers="yes"
    curl_format_curl_off_t=`echo "$curl_format_curl_off_t" | "$SED" 's/[["]]//g'`
    curl_format_curl_off_tu=`echo "$curl_format_curl_off_t" | "$SED" 's/i$/u/'`
    curl_format_curl_off_tu=`echo "$curl_format_curl_off_tu" | "$SED" 's/d$/u/'`
    curl_format_curl_off_tu=`echo "$curl_format_curl_off_tu" | "$SED" 's/D$/U/'`
  else
    x_pull_headers="no"
    case AS_TR_SH([$curl_typeof_curl_off_t]) in
      long_long | __longlong | __longlong_t)
        curl_format_curl_off_t="lld"
        curl_format_curl_off_tu="llu"
        ;;
      long)
        curl_format_curl_off_t="ld"
        curl_format_curl_off_tu="lu"
        ;;
      int)
        curl_format_curl_off_t="d"
        curl_format_curl_off_tu="u"
        ;;
      __int64)
        curl_format_curl_off_t="I64d"
        curl_format_curl_off_tu="I64u"
        ;;
      __int32)
        curl_format_curl_off_t="I32d"
        curl_format_curl_off_tu="I32u"
        ;;
      __int16)
        curl_format_curl_off_t="I16d"
        curl_format_curl_off_tu="I16u"
        ;;
      *)
        AC_MSG_ERROR([cannot find print format string for curl_off_t.])
        ;;
    esac
  fi
  AC_MSG_RESULT(["$curl_format_curl_off_t"])
  #
  AC_MSG_CHECKING([formatting string directive for unsigned curl_off_t])
  AC_MSG_RESULT(["$curl_format_curl_off_tu"])
  #
  DO_CURL_OFF_T_SUFFIX_CHECK([$curl_typeof_curl_off_t])
  #
  if test "$x_pull_headers" = "yes"; then
    if test "x$ac_cv_header_sys_types_h" = "xyes"; then
      CURL_DEFINE_UNQUOTED([CURL_PULL_SYS_TYPES_H])
    fi
    if test "x$ac_cv_header_stdint_h" = "xyes"; then
      CURL_DEFINE_UNQUOTED([CURL_PULL_STDINT_H])
    fi
    if test "x$ac_cv_header_inttypes_h" = "xyes"; then
      CURL_DEFINE_UNQUOTED([CURL_PULL_INTTYPES_H])
    fi
  fi
  #
  CURL_DEFINE_UNQUOTED([CURL_TYPEOF_CURL_OFF_T], [$curl_typeof_curl_off_t])
  CURL_DEFINE_UNQUOTED([CURL_FORMAT_CURL_OFF_T], ["$curl_format_curl_off_t"])
  CURL_DEFINE_UNQUOTED([CURL_FORMAT_CURL_OFF_TU], ["$curl_format_curl_off_tu"])
  CURL_DEFINE_UNQUOTED([CURL_FORMAT_OFF_T], ["%$curl_format_curl_off_t"])
  CURL_DEFINE_UNQUOTED([CURL_SIZEOF_CURL_OFF_T], [$curl_sizeof_curl_off_t])
  CURL_DEFINE_UNQUOTED([CURL_SUFFIX_CURL_OFF_T], [$curl_suffix_curl_off_t])
  CURL_DEFINE_UNQUOTED([CURL_SUFFIX_CURL_OFF_TU], [$curl_suffix_curl_off_tu])
  #
])


dnl CURL_CHECK_WIN32_LARGEFILE
dnl -------------------------------------------------
dnl Check if curl's WIN32 large file will be used

AC_DEFUN([CURL_CHECK_WIN32_LARGEFILE], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_MSG_CHECKING([whether build target supports WIN32 file API])
  curl_win32_file_api="no"
  if test "$ac_cv_header_windows_h" = "yes"; then
    if test x"$enable_largefile" != "xno"; then
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
        ]],[[
#if !defined(_WIN32_WCE) && \
    (defined(__MINGW32__) || \
    (defined(_MSC_VER) && (defined(_WIN32) || defined(_WIN64))))
          int dummy=1;
#else
          WIN32 large file API not supported.
#endif
        ]])
      ],[
        curl_win32_file_api="win32_large_files"
      ])
    fi
    if test "$curl_win32_file_api" = "no"; then
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
        ]],[[
#if defined(_WIN32_WCE) || defined(__MINGW32__) || defined(_MSC_VER)
          int dummy=1;
#else
          WIN32 small file API not supported.
#endif
        ]])
      ],[
        curl_win32_file_api="win32_small_files"
      ])
    fi
  fi
  case "$curl_win32_file_api" in
    win32_large_files)
      AC_MSG_RESULT([yes (large file enabled)])
      AC_DEFINE_UNQUOTED(USE_WIN32_LARGE_FILES, 1,
        [Define to 1 if you are building a Windows target with large file support.])
      ;;
    win32_small_files)
      AC_MSG_RESULT([yes (large file disabled)])
      AC_DEFINE_UNQUOTED(USE_WIN32_LARGE_FILES, 1,
        [Define to 1 if you are building a Windows target without large file support.])
      ;;
    *)
      AC_MSG_RESULT([no])
      ;;
  esac
])

dnl CURL_EXPORT_PCDIR ($pcdir)
dnl ------------------------
dnl if $pcdir is not empty, set PKG_CONFIG_LIBDIR to $pcdir and export
dnl
dnl we need this macro since pkg-config distinguishes among empty and unset
dnl variable while checking PKG_CONFIG_LIBDIR
dnl

AC_DEFUN([CURL_EXPORT_PCDIR], [
    if test -n "$1"; then
      PKG_CONFIG_LIBDIR="$1"
      export PKG_CONFIG_LIBDIR
    fi
])

dnl CURL_CHECK_PKGCONFIG ($module, [$pcdir])
dnl ------------------------
dnl search for the pkg-config tool (if not cross-compiling). Set the PKGCONFIG
dnl variable to hold the path to it, or 'no' if not found/present.
dnl
dnl If pkg-config is present, check that it has info about the $module or
dnl return "no" anyway!
dnl
dnl Optionally PKG_CONFIG_LIBDIR may be given as $pcdir.
dnl

AC_DEFUN([CURL_CHECK_PKGCONFIG], [

    PKGCONFIG="no"

    if test x$cross_compiling = xyes; then
      dnl see if there's a pkg-specific for this host setup
      AC_PATH_PROG( PKGCONFIG, ${host}-pkg-config, no,
                    $PATH:/usr/bin:/usr/local/bin)
    fi

    if test x$PKGCONFIG = xno; then
      AC_PATH_PROG( PKGCONFIG, pkg-config, no, $PATH:/usr/bin:/usr/local/bin)
    fi

    if test x$PKGCONFIG != xno; then
      AC_MSG_CHECKING([for $1 options with pkg-config])
      dnl ask pkg-config about $1
      itexists=`CURL_EXPORT_PCDIR([$2]) dnl
        $PKGCONFIG --exists $1 >/dev/null 2>&1 && echo 1`

      if test -z "$itexists"; then
        dnl pkg-config does not have info about the given module! set the
        dnl variable to 'no'
        PKGCONFIG="no"
        AC_MSG_RESULT([no])
      else
        AC_MSG_RESULT([found])
      fi
    fi
])


dnl CURL_GENERATE_CONFIGUREHELP_PM
dnl -------------------------------------------------
dnl Generate test harness configurehelp.pm module, defining and
dnl initializing some perl variables with values which are known
dnl when the configure script runs. For portability reasons, test
dnl harness needs information on how to run the C preprocessor.

AC_DEFUN([CURL_GENERATE_CONFIGUREHELP_PM], [
  AC_REQUIRE([AC_PROG_CPP])dnl
  tmp_cpp=`eval echo "$ac_cpp" 2>/dev/null`
  if test -z "$tmp_cpp"; then
    tmp_cpp='cpp'
  fi
  cat >./tests/configurehelp.pm <<_EOF
[@%:@] This is a generated file.  Do not edit.

package configurehelp;

use strict;
use warnings;
use Exporter;

use vars qw(
    @ISA
    @EXPORT_OK
    \$Cpreprocessor
    );

@ISA = qw(Exporter);

@EXPORT_OK = qw(
    \$Cpreprocessor
    );

\$Cpreprocessor = '$tmp_cpp';

1;
_EOF
])
