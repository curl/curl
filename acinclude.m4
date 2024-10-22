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
      int main(void)
      {
      #ifdef $1
        return 0;
      #else
        #error force compilation error
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
      int main(void)
      {
      #if defined(__hpux) && defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 600)
        return 0;
      #elif defined(__hpux) && defined(_XOPEN_SOURCE_EXTENDED)
        return 0;
      #else
        #error force compilation error
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
dnl an uniform behavior across all autoconf versions,
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


dnl CURL_CHECK_NATIVE_WINDOWS
dnl -------------------------------------------------
dnl Check if building a native Windows target

AC_DEFUN([CURL_CHECK_NATIVE_WINDOWS], [
  AC_CACHE_CHECK([whether build target is a native Windows one], [curl_cv_native_windows], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        #ifdef _WIN32
          int dummy=1;
        #else
          #error Not a native Windows build target.
        #endif
      ]])
    ],[
      curl_cv_native_windows="yes"
    ],[
      curl_cv_native_windows="no"
    ])
  ])
  AM_CONDITIONAL(DOING_NATIVE_WINDOWS, test "x$curl_cv_native_windows" = xyes)
])


dnl CURL_CHECK_HEADER_LBER
dnl -------------------------------------------------
dnl Check for compilable and valid lber.h header,
dnl and check if it is needed even with ldap.h

AC_DEFUN([CURL_CHECK_HEADER_LBER], [
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_CACHE_CHECK([for lber.h], [curl_cv_header_lber_h], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #undef inline
        #ifdef _WIN32
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
        #ifdef _WIN32
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
        #ifdef _WIN32
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
        LDAP *ldp = ldap_init("0.0.0.0", LDAP_PORT);
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
        #ifdef _WIN32
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
        LDAP *ldp = ldapssl_init("0.0.0.0", LDAPS_PORT, 1);
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


dnl CURL_CHECK_LIBS_WINLDAP
dnl -------------------------------------------------
dnl Check for libraries needed for WINLDAP support,
dnl and prepended to LIBS any needed libraries.
dnl This macro can take an optional parameter with a
dnl whitespace separated list of libraries to check
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
          #ifdef _WIN32
          #ifndef WIN32_LEAN_AND_MEAN
          #define WIN32_LEAN_AND_MEAN
          #endif
          #include <windows.h>
          #include <winldap.h>
          #ifdef HAVE_WINBER_H
          #include <winber.h>
          #endif
          #endif
        ]],[[
          BERVAL *bvp = NULL;
          BerElement *bep = ber_init(bvp);
          LDAP *ldp = ldap_init("0.0.0.0", LDAP_PORT);
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
dnl whitespace separated list of libraries to check
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
    '-lldapsdk -lldapx -lldapssl' \
    '-lldap -llber -lssl -lcrypto'; do

    if test "$curl_cv_ldap_LIBS" = "unknown"; then
      if test -z "$x_nlibs"; then
        LIBS="$curl_cv_save_LIBS"
      else
        LIBS="$x_nlibs $curl_cv_save_LIBS"
      fi
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
          #undef inline
          #ifdef _WIN32
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
          LDAP *ldp = ldap_init("0.0.0.0", LDAP_PORT);
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
      LIBCURL_PC_REQUIRES_PRIVATE="ldap $LIBCURL_PC_REQUIRES_PRIVATE"
      AC_MSG_RESULT([$curl_cv_ldap_LIBS])
      ;;
  esac
  #
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
     #ifdef _WIN32
     #ifndef WIN32_LEAN_AND_MEAN
     #define WIN32_LEAN_AND_MEAN
     #endif
     #include <winsock2.h>
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

dnl CURL_CHECK_FUNC_RECV
dnl -------------------------------------------------
dnl Test if the socket recv() function is available,

AC_DEFUN([CURL_CHECK_FUNC_RECV], [
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  #
  AC_MSG_CHECKING([for recv])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #undef inline
      #ifdef _WIN32
      #ifndef WIN32_LEAN_AND_MEAN
      #define WIN32_LEAN_AND_MEAN
      #endif
      #include <winsock2.h>
      #else
      $curl_includes_bsdsocket
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
    AC_DEFINE_UNQUOTED(HAVE_RECV, 1,
      [Define to 1 if you have the recv function.])
    curl_cv_func_recv="yes"
  else
    AC_MSG_ERROR([Unable to link function recv])
  fi
])


dnl CURL_CHECK_FUNC_SEND
dnl -------------------------------------------------
dnl Test if the socket send() function is available,

AC_DEFUN([CURL_CHECK_FUNC_SEND], [
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  AC_CHECK_HEADERS(sys/types.h sys/socket.h)
  #
  AC_MSG_CHECKING([for send])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #undef inline
      #ifdef _WIN32
      #ifndef WIN32_LEAN_AND_MEAN
      #define WIN32_LEAN_AND_MEAN
      #endif
      #include <winsock2.h>
      #else
      $curl_includes_bsdsocket
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
    AC_DEFINE_UNQUOTED(HAVE_SEND, 1,
      [Define to 1 if you have the send function.])
    curl_cv_func_send="yes"
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
        #ifdef _WIN32
        #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
        #endif
        #include <winsock2.h>
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
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_CHECK_HEADERS(sys/types.h sys/time.h sys/socket.h)
  AC_CACHE_CHECK([for struct timeval], [curl_cv_struct_timeval], [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #undef inline
        #ifdef _WIN32
        #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
        #endif
        #include <winsock2.h>
        #endif
        #ifdef HAVE_SYS_TYPES_H
        #include <sys/types.h>
        #endif
        #ifdef HAVE_SYS_TIME_H
        #include <sys/time.h>
        #endif
        #include <time.h>
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
              #ifdef _WIN32
              #ifndef WIN32_LEAN_AND_MEAN
              #define WIN32_LEAN_AND_MEAN
              #endif
              #include <winsock2.h>
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
    #ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
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
  AC_CHECK_HEADERS(sys/types.h sys/time.h)
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
        #endif
        #include <time.h>
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

dnl CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC_RAW
dnl -------------------------------------------------
dnl Check if monotonic clock_gettime is available.

AC_DEFUN([CURL_CHECK_FUNC_CLOCK_GETTIME_MONOTONIC_RAW], [
  AC_CHECK_HEADERS(sys/types.h sys/time.h)
  AC_MSG_CHECKING([for raw monotonic clock_gettime])
  #
  if test "x$dontwant_rt" = "xno" ; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #ifdef HAVE_SYS_TYPES_H
        #include <sys/types.h>
        #endif
        #ifdef HAVE_SYS_TIME_H
        #include <sys/time.h>
        #endif
        #include <time.h>
      ]],[[
        struct timespec ts;
        (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
      ]])
    ],[
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED(HAVE_CLOCK_GETTIME_MONOTONIC_RAW, 1,
        [Define to 1 if you have the clock_gettime function and raw monotonic timer.])
    ],[
      AC_MSG_RESULT([no])
    ])
  fi
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
            #endif
            #include <time.h>
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
      CURL_RUN_IFELSE([
        AC_LANG_PROGRAM([[
          #include <stdlib.h>
          #ifdef HAVE_SYS_TYPES_H
          #include <sys/types.h>
          #endif
          #ifdef HAVE_SYS_TIME_H
          #include <sys/time.h>
          #endif
          #include <time.h>
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
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  AC_MSG_CHECKING([for connect in libraries])
  tst_connect_save_LIBS="$LIBS"
  tst_connect_need_LIBS="unknown"
  for tst_lib in '' '-lsocket' ; do
    if test "$tst_connect_need_LIBS" = "unknown"; then
      LIBS="$tst_lib $tst_connect_save_LIBS"
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
          $curl_includes_winsock2
          $curl_includes_bsdsocket
          #if !defined(_WIN32) && !defined(HAVE_PROTO_BSDSOCKET_H)
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


dnl CURL_CHECK_FUNC_SELECT
dnl -------------------------------------------------
dnl Test if the socket select() function is available.

AC_DEFUN([CURL_CHECK_FUNC_SELECT], [
  AC_REQUIRE([CURL_CHECK_STRUCT_TIMEVAL])dnl
  AC_REQUIRE([CURL_INCLUDES_BSDSOCKET])dnl
  AC_CHECK_HEADERS(sys/select.h sys/socket.h)
  #
  AC_MSG_CHECKING([for select])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #undef inline
      #ifdef _WIN32
      #ifndef WIN32_LEAN_AND_MEAN
      #define WIN32_LEAN_AND_MEAN
      #endif
      #include <winsock2.h>
      #endif
      #ifdef HAVE_SYS_TYPES_H
      #include <sys/types.h>
      #endif
      #ifdef HAVE_SYS_TIME_H
      #include <sys/time.h>
      #endif
      #include <time.h>
      #ifndef _WIN32
      #ifdef HAVE_SYS_SELECT_H
      #include <sys/select.h>
      #elif defined(HAVE_UNISTD_H)
      #include <unistd.h>
      #endif
      #ifdef HAVE_SYS_SOCKET_H
      #include <sys/socket.h>
      #endif
      $curl_includes_bsdsocket
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
    AC_DEFINE_UNQUOTED(HAVE_SELECT, 1,
      [Define to 1 if you have the select function.])
    curl_cv_func_select="yes"
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
    CURL_RUN_IFELSE([
      int main()
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


dnl CURL_CHECK_CA_BUNDLE
dnl -------------------------------------------------
dnl Check if a default ca-bundle should be used
dnl
dnl regarding the paths this will scan:
dnl /etc/ssl/certs/ca-certificates.crt Debian systems
dnl /etc/pki/tls/certs/ca-bundle.crt Redhat and Mandriva
dnl /usr/share/ssl/certs/ca-bundle.crt old(er) Redhat
dnl /usr/local/share/certs/ca-root-nss.crt MidnightBSD
dnl /etc/ssl/cert.pem OpenBSD, MidnightBSD (symlink)
dnl /etc/ssl/certs (CA path) SUSE, FreeBSD

AC_DEFUN([CURL_CHECK_CA_BUNDLE], [

  AC_MSG_CHECKING([default CA cert bundle/path])

  AC_ARG_WITH(ca-bundle,
AS_HELP_STRING([--with-ca-bundle=FILE],
  [Absolute path to a file containing CA certificates (example: /etc/ca-bundle.crt)])
AS_HELP_STRING([--without-ca-bundle], [Don't use a default CA bundle]),
  [
    want_ca="$withval"
    if test "x$want_ca" = "xyes"; then
      AC_MSG_ERROR([--with-ca-bundle=FILE requires a path to the CA bundle])
    fi
  ],
  [ want_ca="unset" ])
  AC_ARG_WITH(ca-path,
AS_HELP_STRING([--with-ca-path=DIRECTORY],
  [Absolute path to a directory containing CA certificates stored individually, with \
their filenames in a hash format. This option can be used with the OpenSSL, \
GnuTLS, mbedTLS and wolfSSL backends. Refer to OpenSSL c_rehash for details. \
(example: /etc/certificates)])
AS_HELP_STRING([--without-ca-path], [Don't use a default CA path]),
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
    capath="$want_capath"
    ca="no"
  else
    dnl First try auto-detecting a CA bundle, then a CA path.
    dnl Both auto-detections can be skipped by --without-ca-*
    ca="no"
    capath="no"
    if test "x$cross_compiling" != "xyes" -a \
            "x$curl_cv_native_windows" != "xyes"; then
      dnl NOT cross-compiling and...
      dnl neither of the --with-ca-* options are provided
      if test "x$want_ca" = "xunset"; then
        dnl the path we previously would have installed the curl CA bundle
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
      AC_MSG_NOTICE([want $want_capath ca $ca])
      if test "x$want_capath" = "xunset"; then
        check_capath="/etc/ssl/certs"
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
    CURL_CA_BUNDLE="$ca"
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

  AC_MSG_CHECKING([whether to use built-in CA store of SSL library])
  AC_ARG_WITH(ca-fallback,
AS_HELP_STRING([--with-ca-fallback], [Use the built-in CA store of the SSL library])
AS_HELP_STRING([--without-ca-fallback], [Don't use the built-in CA store of the SSL library]),
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
    AC_DEFINE_UNQUOTED(CURL_CA_FALLBACK, 1, [define "1" to use built-in CA store of SSL library])
  fi
])


dnl CURL_CHECK_CA_EMBED
dnl -------------------------------------------------
dnl Check if a ca-bundle should be embedded

AC_DEFUN([CURL_CHECK_CA_EMBED], [

  AC_MSG_CHECKING([CA cert bundle path to embed in the curl tool])

  AC_ARG_WITH(ca-embed,
AS_HELP_STRING([--with-ca-embed=FILE],
  [Absolute path to a file containing CA certificates to embed in the curl tool (example: /etc/ca-bundle.crt)])
AS_HELP_STRING([--without-ca-embed], [Don't embed a default CA bundle in the curl tool]),
  [
    want_ca_embed="$withval"
    if test "x$want_ca_embed" = "xyes"; then
      AC_MSG_ERROR([--with-ca-embed=FILE requires a path to the CA bundle])
    fi
  ],
  [ want_ca_embed="unset" ])

  CURL_CA_EMBED=''
  if test "x$want_ca_embed" != "xno" -a "x$want_ca_embed" != "xunset" -a -f "$want_ca_embed"; then
    CURL_CA_EMBED="$want_ca_embed"
    AC_SUBST(CURL_CA_EMBED)
    AC_MSG_RESULT([$want_ca_embed])
  else
    AC_MSG_RESULT([no])
  fi
])

dnl CURL_CHECK_WIN32_LARGEFILE
dnl -------------------------------------------------
dnl Check if curl's Win32 large file will be used

AC_DEFUN([CURL_CHECK_WIN32_LARGEFILE], [
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_MSG_CHECKING([whether build target supports Win32 file API])
  curl_win32_file_api="no"
  if test "$curl_cv_native_windows" = "yes"; then
    if test x"$enable_largefile" != "xno"; then
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
        ]],[[
          #if !defined(_WIN32_WCE) && (defined(__MINGW32__) || defined(_MSC_VER))
            int dummy=1;
          #else
            #error Win32 large file API not supported.
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
            #error Win32 small file API not supported.
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
      AC_SUBST(USE_WIN32_LARGE_FILES, [1])
      ;;
    win32_small_files)
      AC_MSG_RESULT([yes (large file disabled)])
      AC_DEFINE_UNQUOTED(USE_WIN32_SMALL_FILES, 1,
        [Define to 1 if you are building a Windows target without large file support.])
      AC_SUBST(USE_WIN32_SMALL_FILES, [1])
      ;;
    *)
      AC_MSG_RESULT([no])
      ;;
  esac
])

dnl CURL_CHECK_WIN32_CRYPTO
dnl -------------------------------------------------
dnl Check if curl's Win32 crypto lib can be used

AC_DEFUN([CURL_CHECK_WIN32_CRYPTO], [
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_MSG_CHECKING([whether build target supports Win32 crypto API])
  curl_win32_crypto_api="no"
  if test "$curl_cv_native_windows" = "yes"; then
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #undef inline
        #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
        #endif
        #include <windows.h>
        #include <wincrypt.h>
      ]],[[
        HCRYPTPROV hCryptProv;
        if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
          CryptReleaseContext(hCryptProv, 0);
        }
      ]])
    ],[
      curl_win32_crypto_api="yes"
    ])
  fi
  case "$curl_win32_crypto_api" in
    yes)
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED(USE_WIN32_CRYPTO, 1,
        [Define to 1 if you are building a Windows target with crypto API support.])
      AC_SUBST(USE_WIN32_CRYPTO, [1])
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


dnl CURL_PREPARE_CONFIGUREHELP_PM
dnl -------------------------------------------------
dnl Prepare test harness configurehelp.pm module, defining and
dnl initializing some perl variables with values which are known
dnl when the configure script runs. For portability reasons, test
dnl harness needs information on how to run the C preprocessor.

AC_DEFUN([CURL_PREPARE_CONFIGUREHELP_PM], [
  AC_REQUIRE([AC_PROG_CPP])dnl
  tmp_cpp=`eval echo "$ac_cpp" 2>/dev/null`
  if test -z "$tmp_cpp"; then
    tmp_cpp='cpp'
  fi
  AC_SUBST(CURL_CPP, $tmp_cpp)
])


dnl CURL_PREPARE_BUILDINFO
dnl -------------------------------------------------
dnl Save build info for test runner to pick up and log

AC_DEFUN([CURL_PREPARE_BUILDINFO], [
  curl_pflags=""
  case $host in
    *-apple-*) curl_pflags="${curl_pflags} APPLE";;
  esac
  if test "$curl_cv_native_windows" = 'yes'; then
    curl_pflags="${curl_pflags} WIN32"
  else
    case $host in
      *-*-*bsd*|*-*-aix*|*-*-hpux*|*-*-interix*|*-*-irix*|*-*-linux*|*-*-solaris*|*-*-sunos*|*-apple-*|*-*-cygwin*|*-*-msys*)
        curl_pflags="${curl_pflags} UNIX";;
    esac
    case $host in
      *-*-*bsd*)
        curl_pflags="${curl_pflags} BSD";;
    esac
  fi
  if test "$curl_cv_cygwin" = 'yes'; then
    curl_pflags="${curl_pflags} CYGWIN"
  fi
  case $host_os in
    msys*) curl_pflags="${curl_pflags} MSYS";;
  esac
  if test "x$compiler_id" = 'xGNU_C'; then
    curl_pflags="${curl_pflags} GCC"
  fi
  case $host_os in
    mingw*) curl_pflags="${curl_pflags} MINGW";;
  esac
  if test "x$cross_compiling" = 'xyes'; then
    curl_pflags="${curl_pflags} CROSS"
  fi
  squeeze curl_pflags
  curl_buildinfo="
buildinfo.configure.tool: configure
buildinfo.configure.args: $ac_configure_args
buildinfo.host: $build
buildinfo.host.cpu: $build_cpu
buildinfo.host.os: $build_os
buildinfo.target: $host
buildinfo.target.cpu: $host_cpu
buildinfo.target.os: $host_os
buildinfo.target.flags: $curl_pflags
buildinfo.compiler: $compiler_id
buildinfo.compiler.version: $compiler_ver
buildinfo.sysroot: $lt_sysroot"
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


dnl CURL_DARWIN_CFLAGS
dnl
dnl Set -Werror=partial-availability to detect possible breaking code
dnl with very low deployment targets.
dnl

AC_DEFUN([CURL_DARWIN_CFLAGS], [

  tst_cflags="no"
  case $host in
    *-apple-*)
      tst_cflags="yes"
      ;;
  esac

  AC_MSG_CHECKING([for good-to-use Darwin CFLAGS])
  AC_MSG_RESULT([$tst_cflags]);

  if test "$tst_cflags" = "yes"; then
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
    ]],[[
      if(__builtin_available(macOS 10.12, iOS 5.0, *)) {}
    ]])
  ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED(HAVE_BUILTIN_AVAILABLE, 1,
      [Define to 1 if you have the __builtin_available function.])
  ],[
    AC_MSG_RESULT([no])
  ])
])
