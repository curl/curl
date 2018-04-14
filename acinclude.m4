#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

dnl CURL_CHECK_DEF (SYMBOL, [INCLUDES], [SILENT])
dnl -------------------------------------------------
dnl Use the C preprocessor to find out if the given object-style symbol
dnl is defined and get its expansion. This macro will not use default
dnl includes even if no INCLUDES argument is given. This macro will run
dnl silently when invoked with three arguments. If the expansion would
dnl result in a set of double-quoted strings the returned expansion will
dnl actually be a single double-quoted string concatenating all them.

AC_DEFUN([CURL_CHECK_DEF], [
  AC_REQUIRE([CURL_CPP_P])dnl
  OLDCPPFLAGS=$CPPFLAGS
  # CPPPFLAG comes from CURL_CPP_P
  CPPFLAGS="$CPPFLAGS $CPPPFLAG"
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
      "$SED" 's/.*CURL_DEF_TOKEN[[ ]][[ ]]*//' 2>/dev/null | \
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
  CPPFLAGS=$OLDCPPFLAGS
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
    LIBS="-lxnet $LIBS"
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
  AC_BEFORE([$0], [CURL_CONFIGURE_PULL_SYS_POLL])dnl
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
  AC_CACHE_CHECK([for windows.h], [curl_cv_header_windows_h], [
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
      curl_cv_header_windows_h="yes"
    ],[
      curl_cv_header_windows_h="no"
    ])
  ])
  case "$curl_cv_header_windows_h" in
    yes)
      AC_DEFINE_UNQUOTED(HAVE_WINDOWS_H, 1,
        [Define to 1 if you have the windows.h header file.])
      ;;
  esac
])


dnl CURL_CHECK_NATIVE_WINDOWS
dnl -------------------------------------------------
dnl Check if building a native Windows target

AC_DEFUN([CURL_CHECK_NATIVE_WINDOWS], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([whether build target is a native Windows one], [curl_cv_native_windows], [
    if test "$curl_cv_header_windows_h" = "no"; then
      curl_cv_native_windows="no"
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
        curl_cv_native_windows="yes"
      ],[
        curl_cv_native_windows="no"
      ])
    fi
  ])
  AM_CONDITIONAL(DOING_NATIVE_WINDOWS, test "x$curl_cv_native_windows" = xyes)
])


dnl CURL_CHECK_HEADER_WINSOCK
dnl -------------------------------------------------
dnl Check for compilable and valid winsock.h header

AC_DEFUN([CURL_CHECK_HEADER_WINSOCK], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_CACHE_CHECK([for winsock.h], [curl_cv_header_winsock_h], [
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
      curl_cv_header_winsock_h="yes"
    ],[
      curl_cv_header_winsock_h="no"
    ])
  ])
  case "$curl_cv_header_winsock_h" in
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
  AC_CACHE_CHECK([for winsock2.h], [curl_cv_header_winsock2_h], [
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
      curl_cv_header_winsock2_h="yes"
    ],[
      curl_cv_header_winsock2_h="no"
    ])
  ])
  case "$curl_cv_header_winsock2_h" in
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
  AC_CACHE_CHECK([for ws2tcpip.h], [curl_cv_header_ws2tcpip_h], [
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
      curl_cv_header_ws2tcpip_h="yes"
    ],[
      curl_cv_header_ws2tcpip_h="no"
    ])
  ])
  case "$curl_cv_header_ws2tcpip_h" in
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
  AC_CACHE_CHECK([for winldap.h], [curl_cv_header_winldap_h], [
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
      curl_cv_header_winldap_h="yes"
    ],[
      curl_cv_header_winldap_h="no"
    ])
  ])
  case "$curl_cv_header_winldap_h" in
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
  AC_CACHE_CHECK([for winber.h], [curl_cv_header_winber_h], [
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
      curl_cv_header_winber_h="yes"
    ],[
      curl_cv_header_winber_h="no"
    ])
  ])
  case "$curl_cv_header_winber_h" in
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
  AC_CACHE_CHECK([for lber.h], [curl_cv_header_lber_h], [
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
      curl_cv_header_lber_h="yes"
    ],[
      curl_cv_header_lber_h="no"
    ])
  ])
  if test "$curl_cv_header_lber_h" = "yes"; then
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
  AC_CACHE_CHECK([for ldap.h], [curl_cv_header_ldap_h], [
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
      curl_cv_header_ldap_h="yes"
    ],[
      curl_cv_header_ldap_h="no"
    ])
  ])
  case "$curl_cv_header_ldap_h" in
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
  AC_CACHE_CHECK([for ldap_ssl.h], [curl_cv_header_ldap_ssl_h], [
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
      curl_cv_header_ldap_ssl_h="yes"
    ],[
      curl_cv_header_ldap_ssl_h="no"
    ])
  ])
  case "$curl_cv_header_ldap_ssl_h" in
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
  AC_CACHE_CHECK([for ldapssl.h], [curl_cv_header_ldapssl_h], [
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
      curl_cv_header_ldapssl_h="yes"
    ],[
      curl_cv_header_ldapssl_h="no"
    ])
  ])
  case "$curl_cv_header_ldapssl_h" in
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
    '-lldap -llber' \
    '-llber -lldap' \
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
  AC_CACHE_CHECK([for malloc.h], [curl_cv_header_malloc_h], [
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
      curl_cv_header_malloc_h="yes"
    ],[
      curl_cv_header_malloc_h="no"
    ])
  ])
  if test "$curl_cv_header_malloc_h" = "yes"; then
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
  AC_CACHE_CHECK([for memory.h], [curl_cv_header_memory_h], [
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
      curl_cv_header_memory_h="yes"
    ],[
      curl_cv_header_memory_h="no"
    ])
  ])
  if test "$curl_cv_header_memory_h" = "yes"; then
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
                    extern int GNICALLCONV
#ifdef __ANDROID__
__attribute__((overloadable))
#endif
				getnameinfo($gni_arg1, $gni_arg2,
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
      curl_cv_func_getnameinfo="yes"
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
    [curl_cv_working_ni_withscopeid], [
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
      curl_cv_working_ni_withscopeid="yes"
    ],[
      # Exit code != 0. Program failed.
      curl_cv_working_ni_withscopeid="no"
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
        curl_cv_working_ni_withscopeid="yes"
      ],[
        curl_cv_working_ni_withscopeid="no"
      ]) # AC-COMPILE-IFELSE
    ]) # AC-RUN-IFELSE
  ]) # AC-CACHE-CHECK
  case "$curl_cv_working_ni_withscopeid" in
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
#ifdef __ANDROID__
__attribute__((overloadable))
#endif
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
      curl_cv_func_recv="yes"
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
#ifdef __ANDROID__
__attribute__((overloadable))
#endif
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
      curl_cv_func_send="yes"
    fi
  else
    AC_MSG_ERROR([Unable to link function send])
  fi
])

dnl CURL_CHECK_MSG_NOSIGNAL
dnl -------------------------------------------------
dnl Check for MSG_NOSIGNAL

AC_DEFUN([CURL_CHECK_MSG_NOSIGNAL], [
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  AC_CACHE_CHECK([for MSG_NOSIGNAL], [curl_cv_msg_nosignal], [
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
      curl_cv_msg_nosignal="yes"
    ],[
      curl_cv_msg_nosignal="no"
    ])
  ])
  case "$curl_cv_msg_nosignal" in
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
  AC_CACHE_CHECK([for struct timeval], [curl_cv_struct_timeval], [
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
      curl_cv_struct_timeval="yes"
    ],[
      curl_cv_struct_timeval="no"
    ])
  ])
  case "$curl_cv_struct_timeval" in
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
        curl_cv_sig_atomic_t_volatile="no"
      ],[
        AC_MSG_RESULT([yes])
        curl_cv_sig_atomic_t_volatile="yes"
      ])
      #
      if test "$curl_cv_sig_atomic_t_volatile" = "yes"; then
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
  #
  if test "x$dontwant_rt" = "xno" ; then
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
      curl_func_clock_gettime="yes"
    ],[
      AC_MSG_RESULT([no])
      curl_func_clock_gettime="no"
    ])
  fi
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
  if test "$curl_func_clock_gettime" = "yes"; then
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
        curl_func_clock_gettime="no"
        ;;
      X-)
        AC_MSG_RESULT([no additional lib required])
        curl_func_clock_gettime="yes"
        ;;
      *)
        if test -z "$curl_cv_save_LIBS"; then
          LIBS="$curl_cv_gclk_LIBS"
        else
          LIBS="$curl_cv_gclk_LIBS $curl_cv_save_LIBS"
        fi
        AC_MSG_RESULT([$curl_cv_gclk_LIBS])
        curl_func_clock_gettime="yes"
        ;;
    esac
    #
    dnl only do runtime verification when not cross-compiling
    if test "x$cross_compiling" != "xyes" &&
      test "$curl_func_clock_gettime" = "yes"; then
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
        curl_func_clock_gettime="no"
        LIBS="$curl_cv_save_LIBS"
      ])
    fi
    #
    case "$curl_func_clock_gettime" in
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


dnl CURL_CONFIGURE_CURL_SOCKLEN_T
dnl -------------------------------------------------
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
  AC_BEFORE([$0], [CURL_CONFIGURE_PULL_SYS_POLL])dnl
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
  if test "$curl_cv_header_ws2tcpip_h" = "yes"; then
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


dnl CURL_CONFIGURE_PULL_SYS_POLL
dnl -------------------------------------------------
dnl The need for the sys/poll.h inclusion arises mainly to properly
dnl interface AIX systems which define macros 'events' and 'revents'.

AC_DEFUN([CURL_CONFIGURE_PULL_SYS_POLL], [
  AC_REQUIRE([CURL_INCLUDES_POLL])dnl
  #
  tst_poll_events_macro_defined="unknown"
  #
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      $curl_includes_poll
    ]],[[
#if defined(events) || defined(revents)
      return 0;
#else
      force compilation error
#endif
    ]])
  ],[
    tst_poll_events_macro_defined="yes"
  ],[
    tst_poll_events_macro_defined="no"
  ])
  #
  if test "$tst_poll_events_macro_defined" = "yes"; then
    if test "x$ac_cv_header_sys_poll_h" = "xyes"; then
      CURL_DEFINE_UNQUOTED([CURL_PULL_SYS_POLL_H])
    fi
  fi
  #
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
                    extern $sel_retv SELECTCALLCONV
#ifdef __ANDROID__
__attribute__((overloadable))
#endif
			select($sel_arg1,
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
      curl_cv_func_select="yes"
    fi
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
dnl /usr/local/share/certs/ca-root-nss.crt FreeBSD
dnl /etc/ssl/cert.pem OpenBSD, FreeBSD (symlink)
dnl /etc/ssl/certs/ (ca path) SUSE

AC_DEFUN([CURL_CHECK_CA_BUNDLE], [

  AC_MSG_CHECKING([default CA cert bundle/path])

  AC_ARG_WITH(ca-bundle,
AC_HELP_STRING([--with-ca-bundle=FILE],
[Path to a file containing CA certificates (example: /etc/ca-bundle.crt)])
AC_HELP_STRING([--without-ca-bundle], [Don't use a default CA bundle]),
  [
    want_ca="$withval"
    if test "x$want_ca" = "xyes"; then
      AC_MSG_ERROR([--with-ca-bundle=FILE requires a path to the CA bundle])
    fi
  ],
  [ want_ca="unset" ])
  AC_ARG_WITH(ca-path,
AC_HELP_STRING([--with-ca-path=DIRECTORY],
[Path to a directory containing CA certificates stored individually, with \
their filenames in a hash format. This option can be used with OpenSSL, \
GnuTLS and PolarSSL backends. Refer to OpenSSL c_rehash for details. \
(example: /etc/certificates)])
AC_HELP_STRING([--without-ca-path], [Don't use a default CA path]),
  [
    want_capath="$withval"
    if test "x$want_capath" = "xyes"; then
      AC_MSG_ERROR([--with-ca-path=DIRECTORY requires a path to the CA path directory])
    fi
  ],
  [ want_capath="unset"])

  ca_warning="   (warning: certs not found)"
  capath_warning="   (warning: certs not found)"
  check_capath=""

  if test "x$want_ca" != "xno" -a "x$want_ca" != "xunset" -a \
          "x$want_capath" != "xno" -a "x$want_capath" != "xunset"; then
    dnl both given
    ca="$want_ca"
    capath="$want_capath"
  elif test "x$want_ca" != "xno" -a "x$want_ca" != "xunset"; then
    dnl --with-ca-bundle given
    ca="$want_ca"
    capath="no"
  elif test "x$want_capath" != "xno" -a "x$want_capath" != "xunset"; then
    dnl --with-ca-path given
    if test "x$OPENSSL_ENABLED" != "x1" -a "x$GNUTLS_ENABLED" != "x1" -a "x$POLARSSL_ENABLED" != "x1"; then
      AC_MSG_ERROR([--with-ca-path only works with OpenSSL, GnuTLS or PolarSSL])
    fi
    capath="$want_capath"
    ca="no"
  else
    dnl first try autodetecting a CA bundle , then a CA path
    dnl both autodetections can be skipped by --without-ca-*
    ca="no"
    capath="no"
    if test "x$cross_compiling" != "xyes"; then
      dnl NOT cross-compiling and...
      dnl neither of the --with-ca-* options are provided
      if test "x$want_ca" = "xunset"; then
        dnl the path we previously would have installed the curl ca bundle
        dnl to, and thus we now check for an already existing cert in that
        dnl place in case we find no other
        if test "x$prefix" != xNONE; then
          cac="${prefix}/share/curl/curl-ca-bundle.crt"
        else
          cac="$ac_default_prefix/share/curl/curl-ca-bundle.crt"
        fi

        for a in /etc/ssl/certs/ca-certificates.crt \
                 /etc/pki/tls/certs/ca-bundle.crt \
                 /usr/share/ssl/certs/ca-bundle.crt \
                 /usr/local/share/certs/ca-root-nss.crt \
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
        check_capath="/etc/ssl/certs/"
      fi
    else
      dnl no option given and cross-compiling
      AC_MSG_WARN([skipped the ca-cert path detection when cross-compiling])
    fi
  fi

  if test "x$ca" = "xno" || test -f "$ca"; then
    ca_warning=""
  fi

  if test "x$capath" != "xno"; then
    check_capath="$capath"
  fi

  if test ! -z "$check_capath"; then
    for a in "$check_capath"; do
      if test -d "$a" && ls "$a"/[[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]].0 >/dev/null 2>/dev/null; then
        if test "x$capath" = "xno"; then
          capath="$a"
        fi
        capath_warning=""
        break
      fi
    done
  fi

  if test "x$capath" = "xno"; then
    capath_warning=""
  fi

  if test "x$ca" != "xno"; then
    CURL_CA_BUNDLE='"'$ca'"'
    AC_DEFINE_UNQUOTED(CURL_CA_BUNDLE, "$ca", [Location of default ca bundle])
    AC_SUBST(CURL_CA_BUNDLE)
    AC_MSG_RESULT([$ca])
  fi
  if test "x$capath" != "xno"; then
    CURL_CA_PATH="\"$capath\""
    AC_DEFINE_UNQUOTED(CURL_CA_PATH, "$capath", [Location of default ca path])
    AC_MSG_RESULT([$capath (capath)])
  fi
  if test "x$ca" = "xno" && test "x$capath" = "xno"; then
    AC_MSG_RESULT([no])
  fi

  AC_MSG_CHECKING([whether to use builtin CA store of SSL library])
  AC_ARG_WITH(ca-fallback,
AC_HELP_STRING([--with-ca-fallback], [Use the built in CA store of the SSL library])
AC_HELP_STRING([--without-ca-fallback], [Don't use the built in CA store of the SSL library]),
  [
    if test "x$with_ca_fallback" != "xyes" -a "x$with_ca_fallback" != "xno"; then
      AC_MSG_ERROR([--with-ca-fallback only allows yes or no as parameter])
    fi
  ],
  [ with_ca_fallback="no"])
  AC_MSG_RESULT([$with_ca_fallback])
  if test "x$with_ca_fallback" = "xyes"; then
    if test "x$OPENSSL_ENABLED" != "x1" -a "x$GNUTLS_ENABLED" != "x1"; then
      AC_MSG_ERROR([--with-ca-fallback only works with OpenSSL or GnuTLS])
    fi
    AC_DEFINE_UNQUOTED(CURL_CA_FALLBACK, 1, [define "1" to use built in CA store of SSL library ])
  fi
])

dnl CURL_CHECK_WIN32_LARGEFILE
dnl -------------------------------------------------
dnl Check if curl's WIN32 large file will be used

AC_DEFUN([CURL_CHECK_WIN32_LARGEFILE], [
  AC_REQUIRE([CURL_CHECK_HEADER_WINDOWS])dnl
  AC_MSG_CHECKING([whether build target supports WIN32 file API])
  curl_win32_file_api="no"
  if test "$curl_cv_header_windows_h" = "yes"; then
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
      AC_DEFINE_UNQUOTED(USE_WIN32_SMALL_FILES, 1,
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
dnl search for the pkg-config tool. Set the PKGCONFIG variable to hold the
dnl path to it, or 'no' if not found/present.
dnl
dnl If pkg-config is present, check that it has info about the $module or
dnl return "no" anyway!
dnl
dnl Optionally PKG_CONFIG_LIBDIR may be given as $pcdir.
dnl

AC_DEFUN([CURL_CHECK_PKGCONFIG], [
    if test -n "$PKG_CONFIG"; then
      PKGCONFIG="$PKG_CONFIG"
    else
      AC_PATH_TOOL([PKGCONFIG], [pkg-config], [no],
        [$PATH:/usr/bin:/usr/local/bin])
    fi

    if test "x$PKGCONFIG" != "xno"; then
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

dnl CURL_CPP_P
dnl
dnl Check if $cpp -P should be used for extract define values due to gcc 5
dnl splitting up strings and defines between line outputs. gcc by default
dnl (without -P) will show TEST EINVAL TEST as
dnl
dnl # 13 "conftest.c"
dnl TEST
dnl # 13 "conftest.c" 3 4
dnl     22
dnl # 13 "conftest.c"
dnl            TEST

AC_DEFUN([CURL_CPP_P], [
  AC_MSG_CHECKING([if cpp -P is needed])
  AC_EGREP_CPP([TEST.*TEST], [
 #include <errno.h>
TEST EINVAL TEST
  ], [cpp=no], [cpp=yes])
  AC_MSG_RESULT([$cpp])

  dnl we need cpp -P so check if it works then
  if test "x$cpp" = "xyes"; then
    AC_MSG_CHECKING([if cpp -P works])
    OLDCPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS -P"
    AC_EGREP_CPP([TEST.*TEST], [
 #include <errno.h>
TEST EINVAL TEST
    ], [cpp_p=yes], [cpp_p=no])
    AC_MSG_RESULT([$cpp_p])

    if test "x$cpp_p" = "xno"; then
      AC_MSG_WARN([failed to figure out cpp -P alternative])
      # without -P
      CPPPFLAG=""
    else
      # with -P
      CPPPFLAG="-P"
    fi
    dnl restore CPPFLAGS
    CPPFLAGS=$OLDCPPFLAGS
  else
    # without -P
    CPPPFLAG=""
  fi
])


dnl CURL_MAC_CFLAGS
dnl
dnl Check if -mmacosx-version-min, -miphoneos-version-min or any
dnl similar are set manually, otherwise do. And set
dnl -Werror=partial-availability.
dnl

AC_DEFUN([CURL_MAC_CFLAGS], [

  tst_cflags="no"
  case $host_os in
    darwin*)
      tst_cflags="yes"
      ;;
  esac

  AC_MSG_CHECKING([for good-to-use Mac CFLAGS])
  AC_MSG_RESULT([$tst_cflags]);

  if test "$tst_cflags" = "yes"; then
    AC_MSG_CHECKING([for *version-min in CFLAGS])
    min=""
    if test -z "$(echo $CFLAGS | grep m.*os.*-version-min)"; then
      min="-mmacosx-version-min=10.8"
      CFLAGS="$CFLAGS $min"
    fi
    if test -z "$min"; then
      AC_MSG_RESULT([set by user])
    else
      AC_MSG_RESULT([$min set])
    fi

    old_CFLAGS=$CFLAGS
    CFLAGS="$CFLAGS -Werror=partial-availability"
    AC_MSG_CHECKING([whether $CC accepts -Werror=partial-availability])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
      [AC_MSG_RESULT([yes])],
      [AC_MSG_RESULT([no])
      CFLAGS=$old_CFLAGS])
  fi

])


dnl CURL_SUPPORTS_BUILTIN_AVAILABLE
dnl
dnl Check to see if the compiler supports __builtin_available. This built-in
dnl compiler function first appeared in Apple LLVM 9.0.0. It's so new that, at
dnl the time this macro was written, the function was not yet documented. Its
dnl purpose is to return true if the code is running under a certain OS version
dnl or later.

AC_DEFUN([CURL_SUPPORTS_BUILTIN_AVAILABLE], [
  AC_MSG_CHECKING([to see if the compiler supports __builtin_available()])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#include <stdlib.h>
    ]],[[
      if (__builtin_available(macOS 10.8, iOS 5.0, *)) {}
    ]])
  ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_BUILTIN_AVAILABLE, 1,
        [Define to 1 if you have the __builtin_available function.])
  ],[
    AC_MSG_RESULT([no])
  ])
])
