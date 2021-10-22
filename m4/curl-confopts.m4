#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 19

dnl CURL_CHECK_OPTION_THREADED_RESOLVER
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-threaded-resolver or --disable-threaded-resolver, and
dnl set shell variable want_thres as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_THREADED_RESOLVER], [
  AC_MSG_CHECKING([whether to enable the threaded resolver])
  OPT_THRES="default"
  AC_ARG_ENABLE(threaded_resolver,
AS_HELP_STRING([--enable-threaded-resolver],[Enable threaded resolver])
AS_HELP_STRING([--disable-threaded-resolver],[Disable threaded resolver]),
  OPT_THRES=$enableval)
  case "$OPT_THRES" in
    no)
      dnl --disable-threaded-resolver option used
      want_thres="no"
      ;;
    *)
      dnl configure option not specified
      want_thres="yes"
      ;;
  esac
  AC_MSG_RESULT([$want_thres])
])

dnl CURL_CHECK_OPTION_ARES
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-ares or --disable-ares, and
dnl set shell variable want_ares as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_ARES], [
dnl   AC_BEFORE([$0],[CURL_CHECK_OPTION_THREADS])dnl
  AC_BEFORE([$0],[CURL_CHECK_LIB_ARES])dnl
  AC_MSG_CHECKING([whether to enable c-ares for DNS lookups])
  OPT_ARES="default"
  AC_ARG_ENABLE(ares,
AS_HELP_STRING([--enable-ares@<:@=PATH@:>@],[Enable c-ares for DNS lookups])
AS_HELP_STRING([--disable-ares],[Disable c-ares for DNS lookups]),
  OPT_ARES=$enableval)
  case "$OPT_ARES" in
    no)
      dnl --disable-ares option used
      want_ares="no"
      ;;
    default)
      dnl configure option not specified
      want_ares="no"
      ;;
    *)
      dnl --enable-ares option used
      want_ares="yes"
      if test -n "$enableval" && test "$enableval" != "yes"; then
        want_ares_path="$enableval"
      fi
      ;;
  esac
  AC_MSG_RESULT([$want_ares])
])


dnl CURL_CHECK_OPTION_CURLDEBUG
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-curldebug or --disable-curldebug, and set
dnl shell variable want_curldebug value as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_CURLDEBUG], [
  AC_BEFORE([$0],[CURL_CHECK_CURLDEBUG])dnl
  AC_MSG_CHECKING([whether to enable curl debug memory tracking])
  OPT_CURLDEBUG_BUILD="default"
  AC_ARG_ENABLE(curldebug,
AS_HELP_STRING([--enable-curldebug],[Enable curl debug memory tracking])
AS_HELP_STRING([--disable-curldebug],[Disable curl debug memory tracking]),
  OPT_CURLDEBUG_BUILD=$enableval)
  case "$OPT_CURLDEBUG_BUILD" in
    no)
      dnl --disable-curldebug option used
      want_curldebug="no"
      AC_MSG_RESULT([no])
      ;;
    default)
      dnl configure's curldebug option not specified. Initially we will
      dnl handle this as a request to use the same setting as option
      dnl --enable-debug. IOW, initially, for debug-enabled builds
      dnl this will be handled as a request to enable curldebug if
      dnl possible, and for debug-disabled builds this will be handled
      dnl as a request to disable curldebug.
      if test "$want_debug" = "yes"; then
        AC_MSG_RESULT([(assumed) yes])
        AC_DEFINE(CURLDEBUG, 1, [to enable curl debug memory tracking])
      else
        AC_MSG_RESULT([no])
      fi
      want_curldebug_assumed="yes"
      want_curldebug="$want_debug"
      ;;
    *)
      dnl --enable-curldebug option used.
      dnl The use of this option value is a request to enable curl's
      dnl debug memory tracking for the libcurl library. This can only
      dnl be done when some requisites are simultaneously satisfied.
      dnl Later on, these requisites are verified and if they are not
      dnl fully satisfied the option will be ignored and act as if
      dnl --disable-curldebug had been given setting shell variable
      dnl want_curldebug to 'no'.
      want_curldebug="yes"
      AC_DEFINE(CURLDEBUG, 1, [to enable curl debug memory tracking])
      AC_MSG_RESULT([yes])
      ;;
  esac
])


dnl CURL_CHECK_OPTION_DEBUG
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-debug or --disable-debug, and set shell
dnl variable want_debug value as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_DEBUG], [
  AC_BEFORE([$0],[CURL_CHECK_OPTION_WARNINGS])dnl
  AC_BEFORE([$0],[CURL_CHECK_OPTION_CURLDEBUG])dnl
  AC_BEFORE([$0],[XC_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable debug build options])
  OPT_DEBUG_BUILD="default"
  AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],[Enable debug build options])
AS_HELP_STRING([--disable-debug],[Disable debug build options]),
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
      AC_DEFINE(DEBUGBUILD, 1, [enable debug build options])
      ;;
  esac
  AC_MSG_RESULT([$want_debug])
])

dnl CURL_CHECK_OPTION_OPTIMIZE
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-optimize or --disable-optimize, and set
dnl shell variable want_optimize value as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_OPTIMIZE], [
  AC_REQUIRE([CURL_CHECK_OPTION_DEBUG])dnl
  AC_BEFORE([$0],[XC_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable compiler optimizer])
  OPT_COMPILER_OPTIMIZE="default"
  AC_ARG_ENABLE(optimize,
AS_HELP_STRING([--enable-optimize],[Enable compiler optimizations])
AS_HELP_STRING([--disable-optimize],[Disable compiler optimizations]),
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
      dnl handle this as a request contrary to configure's setting
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
        AC_MSG_RESULT([(assumed) no])
      else
        want_optimize="assume_yes"
        AC_MSG_RESULT([(assumed) yes])
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


dnl CURL_CHECK_OPTION_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-symbol-hiding or --disable-symbol-hiding,
dnl setting shell variable want_symbol_hiding value.

AC_DEFUN([CURL_CHECK_OPTION_SYMBOL_HIDING], [
  AC_BEFORE([$0],[CURL_CHECK_COMPILER_SYMBOL_HIDING])dnl
  AC_MSG_CHECKING([whether to enable hiding of library internal symbols])
  OPT_SYMBOL_HIDING="default"
  AC_ARG_ENABLE(symbol-hiding,
AS_HELP_STRING([--enable-symbol-hiding],[Enable hiding of library internal symbols])
AS_HELP_STRING([--disable-symbol-hiding],[Disable hiding of library internal symbols]),
  OPT_SYMBOL_HIDING=$enableval)
  case "$OPT_SYMBOL_HIDING" in
    no)
      dnl --disable-symbol-hiding option used.
      dnl This is an indication to not attempt hiding of library internal
      dnl symbols. Default symbol visibility will be used, which normally
      dnl exposes all library internal symbols.
      want_symbol_hiding="no"
      AC_MSG_RESULT([no])
      ;;
    default)
      dnl configure's symbol-hiding option not specified.
      dnl Handle this as if --enable-symbol-hiding option was given.
      want_symbol_hiding="yes"
      AC_MSG_RESULT([yes])
      ;;
    *)
      dnl --enable-symbol-hiding option used.
      dnl This is an indication to attempt hiding of library internal
      dnl symbols. This is only supported on some compilers/linkers.
      want_symbol_hiding="yes"
      AC_MSG_RESULT([yes])
      ;;
  esac
])


dnl CURL_CHECK_OPTION_THREADS
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-threads or --disable-threads, and
dnl set shell variable want_threads as appropriate.

dnl AC_DEFUN([CURL_CHECK_OPTION_THREADS], [
dnl   AC_BEFORE([$0],[CURL_CHECK_LIB_THREADS])dnl
dnl   AC_MSG_CHECKING([whether to enable threads for DNS lookups])
dnl   OPT_THREADS="default"
dnl   AC_ARG_ENABLE(threads,
dnl AS_HELP_STRING([--enable-threads@<:@=PATH@:>@],[Enable threads for DNS lookups])
dnl AS_HELP_STRING([--disable-threads],[Disable threads for DNS lookups]),
dnl   OPT_THREADS=$enableval)
dnl   case "$OPT_THREADS" in
dnl     no)
dnl       dnl --disable-threads option used
dnl       want_threads="no"
dnl       AC_MSG_RESULT([no])
dnl       ;;
dnl     default)
dnl       dnl configure option not specified
dnl       want_threads="no"
dnl       AC_MSG_RESULT([(assumed) no])
dnl       ;;
dnl     *)
dnl       dnl --enable-threads option used
dnl       want_threads="yes"
dnl       want_threads_path="$enableval"
dnl       AC_MSG_RESULT([yes])
dnl       ;;
dnl   esac
dnl   #
dnl   if test "$want_ares" = "assume_yes"; then
dnl     if test "$want_threads" = "yes"; then
dnl       AC_MSG_CHECKING([whether to ignore c-ares enabling assumed setting])
dnl       AC_MSG_RESULT([yes])
dnl       want_ares="no"
dnl     else
dnl       want_ares="yes"
dnl     fi
dnl   fi
dnl   if test "$want_threads" = "yes" && test "$want_ares" = "yes"; then
dnl     AC_MSG_ERROR([options --enable-ares and --enable-threads are mutually exclusive, at most one may be enabled.])
dnl   fi
dnl ])

dnl CURL_CHECK_OPTION_RT
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --disable-rt and set shell variable dontwant_rt
dnl as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_RT], [
  AC_BEFORE([$0], [CURL_CHECK_LIB_THREADS])dnl
  AC_MSG_CHECKING([whether to disable dependency on -lrt])
  OPT_RT="default"
  AC_ARG_ENABLE(rt,
 AS_HELP_STRING([--disable-rt],[disable dependency on -lrt]),
  OPT_RT=$enableval)
  case "$OPT_RT" in
    no)
      dnl --disable-rt used (reverse logic)
      dontwant_rt="yes"
      AC_MSG_RESULT([yes])
      ;;
    default)
      dnl configure option not specified (so not disabled)
      dontwant_rt="no"
      AC_MSG_RESULT([(assumed no)])
      ;;
    *)
      dnl --enable-rt option used (reverse logic)
      dontwant_rt="no"
      AC_MSG_RESULT([no])
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
  AC_BEFORE([$0],[CURL_CHECK_OPTION_WERROR])dnl
  AC_BEFORE([$0],[XC_CHECK_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable strict compiler warnings])
  OPT_COMPILER_WARNINGS="default"
  AC_ARG_ENABLE(warnings,
AS_HELP_STRING([--enable-warnings],[Enable strict compiler warnings])
AS_HELP_STRING([--disable-warnings],[Disable strict compiler warnings]),
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

dnl CURL_CHECK_OPTION_WERROR
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-werror or --disable-werror, and set
dnl shell variable want_werror as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_WERROR], [
  AC_BEFORE([$0],[CURL_CHECK_COMPILER])dnl
  AC_MSG_CHECKING([whether to enable compiler warnings as errors])
  OPT_COMPILER_WERROR="default"
  AC_ARG_ENABLE(werror,
AS_HELP_STRING([--enable-werror],[Enable compiler warnings as errors])
AS_HELP_STRING([--disable-werror],[Disable compiler warnings as errors]),
  OPT_COMPILER_WERROR=$enableval)
  case "$OPT_COMPILER_WERROR" in
    no)
      dnl --disable-werror option used
      want_werror="no"
      ;;
    default)
      dnl configure option not specified
      want_werror="no"
      ;;
    *)
      dnl --enable-werror option used
      want_werror="yes"
      ;;
  esac
  AC_MSG_RESULT([$want_werror])
])


dnl CURL_CHECK_NONBLOCKING_SOCKET
dnl -------------------------------------------------
dnl Check for how to set a socket into non-blocking state.

AC_DEFUN([CURL_CHECK_NONBLOCKING_SOCKET], [
  AC_REQUIRE([CURL_CHECK_FUNC_FCNTL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTLSOCKET])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL])dnl
  AC_REQUIRE([CURL_CHECK_FUNC_SETSOCKOPT])dnl
  #
  tst_method="unknown"

  AC_MSG_CHECKING([how to set a socket into non-blocking mode])
  if test "x$curl_cv_func_fcntl_o_nonblock" = "xyes"; then
    tst_method="fcntl O_NONBLOCK"
  elif test "x$curl_cv_func_ioctl_fionbio" = "xyes"; then
    tst_method="ioctl FIONBIO"
  elif test "x$curl_cv_func_ioctlsocket_fionbio" = "xyes"; then
    tst_method="ioctlsocket FIONBIO"
  elif test "x$curl_cv_func_ioctlsocket_camel_fionbio" = "xyes"; then
    tst_method="IoctlSocket FIONBIO"
  elif test "x$curl_cv_func_setsockopt_so_nonblock" = "xyes"; then
    tst_method="setsockopt SO_NONBLOCK"
  fi
  AC_MSG_RESULT([$tst_method])
  if test "$tst_method" = "unknown"; then
    AC_MSG_WARN([cannot determine non-blocking socket method.])
  fi
])


dnl CURL_CONFIGURE_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Depending on --enable-symbol-hiding or --disable-symbol-hiding
dnl configure option, and compiler capability to actually honor such
dnl option, this will modify compiler flags as appropriate and also
dnl provide needed definitions for configuration and Makefile.am files.
dnl This macro should not be used until all compilation tests have
dnl been done to prevent interferences on other tests.

AC_DEFUN([CURL_CONFIGURE_SYMBOL_HIDING], [
  AC_MSG_CHECKING([whether hiding of library internal symbols will actually happen])
  CFLAG_CURL_SYMBOL_HIDING=""
  doing_symbol_hiding="no"
  if test x"$curl_cv_native_windows" != "xyes" &&
    test "$want_symbol_hiding" = "yes" &&
    test "$supports_symbol_hiding" = "yes"; then
    doing_symbol_hiding="yes"
    CFLAG_CURL_SYMBOL_HIDING="$symbol_hiding_CFLAGS"
    AC_DEFINE_UNQUOTED(CURL_EXTERN_SYMBOL, $symbol_hiding_EXTERN,
      [Definition to make a library symbol externally visible.])
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
  AM_CONDITIONAL(DOING_CURL_SYMBOL_HIDING, test x$doing_symbol_hiding = xyes)
  AC_SUBST(CFLAG_CURL_SYMBOL_HIDING)
])


dnl CURL_CHECK_LIB_ARES
dnl -------------------------------------------------
dnl When c-ares library support has been requested,
dnl performs necessary checks and adjustsments needed
dnl to enable support of this library.

AC_DEFUN([CURL_CHECK_LIB_ARES], [
  #
  if test "$want_ares" = "yes"; then
    dnl c-ares library support has been requested
    clean_CPPFLAGS="$CPPFLAGS"
    clean_LDFLAGS="$LDFLAGS"
    clean_LIBS="$LIBS"
    embedded_ares="unknown"
    configure_runpath=`pwd`
    embedded_ares_builddir="$configure_runpath/ares"
    if test -n "$want_ares_path"; then
      dnl c-ares library path has been specified
      ARES_PCDIR="$want_ares_path/lib/pkgconfig"
      CURL_CHECK_PKGCONFIG(libcares, [$ARES_PCDIR])
      if test "$PKGCONFIG" != "no" ; then
        ares_LIBS=`CURL_EXPORT_PCDIR([$ARES_PCDIR])
          $PKGCONFIG --libs-only-l libcares`
        ares_LDFLAGS=`CURL_EXPORT_PCDIR([$ARES_PCDIR])
          $PKGCONFIG --libs-only-L libcares`
        ares_CPPFLAGS=`CURL_EXPORT_PCDIR([$ARES_PCDIR])
          $PKGCONFIG --cflags-only-I libcares`
        AC_MSG_NOTICE([pkg-config: ares LIBS: "$ares_LIBS"])
        AC_MSG_NOTICE([pkg-config: ares LDFLAGS: "$ares_LDFLAGS"])
        AC_MSG_NOTICE([pkg-config: ares CPPFLAGS: "$ares_CPPFLAGS"])
      else
        dnl ... path without pkg-config
        ares_CPPFLAGS="-I$want_ares_path/include"
        ares_LDFLAGS="-L$want_ares_path/lib"
        ares_LIBS="-lcares"
      fi
    else
      dnl c-ares library path has not been given
      if test -d "$srcdir/ares"; then
        dnl c-ares sources embedded in curl tree
        embedded_ares="yes"
        AC_CONFIG_SUBDIRS(ares)
        dnl c-ares has installable configured header files, path
        dnl inclusion fully done in makefiles for in-tree builds.
        ares_CPPFLAGS=""
        ares_LDFLAGS="-L$embedded_ares_builddir"
        ares_LIBS="-lcares"
      else
        dnl c-ares path not specified, use defaults
        CURL_CHECK_PKGCONFIG(libcares)
        if test "$PKGCONFIG" != "no" ; then
          ares_LIBS=`$PKGCONFIG --libs-only-l libcares`
          ares_LDFLAGS=`$PKGCONFIG --libs-only-L libcares`
          ares_CPPFLAGS=`$PKGCONFIG --cflags-only-I libcares`
          AC_MSG_NOTICE([pkg-config: ares_LIBS: "$ares_LIBS"])
          AC_MSG_NOTICE([pkg-config: ares_LDFLAGS: "$ares_LDFLAGS"])
          AC_MSG_NOTICE([pkg-config: ares_CPPFLAGS: "$ares_CPPFLAGS"])
        else
          ares_CPPFLAGS=""
          ares_LDFLAGS=""
          ares_LIBS="-lcares"
        fi
      fi
    fi
    #
    CPPFLAGS="$clean_CPPFLAGS $ares_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS $ares_LDFLAGS"
    LIBS="$ares_LIBS $clean_LIBS"
    #
    if test "$embedded_ares" != "yes"; then
      dnl check if c-ares new enough when not using an embedded
      dnl source tree one which normally has not been built yet.
      AC_MSG_CHECKING([that c-ares is good and recent enough])
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
#include <ares.h>
          /* set of dummy functions in case c-ares was built with debug */
          void curl_dofree() { }
          void curl_sclose() { }
          void curl_domalloc() { }
          void curl_docalloc() { }
          void curl_socket() { }
        ]],[[
          ares_channel channel;
          ares_cancel(channel); /* added in 1.2.0 */
          ares_process_fd(channel, 0, 0); /* added in 1.4.0 */
          ares_dup(&channel, channel); /* added in 1.6.0 */
        ]])
      ],[
        AC_MSG_RESULT([yes])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([c-ares library defective or too old])
        dnl restore initial settings
        CPPFLAGS="$clean_CPPFLAGS"
        LDFLAGS="$clean_LDFLAGS"
        LIBS="$clean_LIBS"
        # prevent usage
        want_ares="no"
      ])
    fi
    if test "$want_ares" = "yes"; then
      dnl finally c-ares will be used
      AC_DEFINE(USE_ARES, 1, [Define to enable c-ares support])
      AC_SUBST([USE_ARES], [1])
      curl_res_msg="c-ares"
    fi
  fi
])


dnl CURL_CHECK_OPTION_NTLM_WB
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-ntlm-wb or --disable-ntlm-wb, and set
dnl shell variable want_ntlm_wb and want_ntlm_wb_file
dnl as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_NTLM_WB], [
  AC_BEFORE([$0],[CURL_CHECK_NTLM_WB])dnl
  OPT_NTLM_WB="default"
  AC_ARG_ENABLE(ntlm-wb,
AS_HELP_STRING([--enable-ntlm-wb@<:@=FILE@:>@],[Enable NTLM delegation to winbind's ntlm_auth helper, where FILE is ntlm_auth's absolute filename (default: /usr/bin/ntlm_auth)])
AS_HELP_STRING([--disable-ntlm-wb],[Disable NTLM delegation to winbind's ntlm_auth helper]),
  OPT_NTLM_WB=$enableval)
  want_ntlm_wb_file="/usr/bin/ntlm_auth"
  case "$OPT_NTLM_WB" in
    no)
      dnl --disable-ntlm-wb option used
      want_ntlm_wb="no"
      ;;
    default)
      dnl configure option not specified
      want_ntlm_wb="yes"
      ;;
    *)
      dnl --enable-ntlm-wb option used
      want_ntlm_wb="yes"
      if test -n "$enableval" && test "$enableval" != "yes"; then
        want_ntlm_wb_file="$enableval"
      fi
      ;;
  esac
])


dnl CURL_CHECK_NTLM_WB
dnl -------------------------------------------------
dnl Check if support for NTLM delegation to winbind's
dnl ntlm_auth helper will finally be enabled depending
dnl on given configure options and target platform.

AC_DEFUN([CURL_CHECK_NTLM_WB], [
  AC_REQUIRE([CURL_CHECK_OPTION_NTLM_WB])dnl
  AC_REQUIRE([CURL_CHECK_NATIVE_WINDOWS])dnl
  AC_MSG_CHECKING([whether to enable NTLM delegation to winbind's helper])
  if test "$curl_cv_native_windows" = "yes" ||
    test "x$SSL_ENABLED" = "x"; then
    want_ntlm_wb_file=""
    want_ntlm_wb="no"
  fi
  AC_MSG_RESULT([$want_ntlm_wb])
  if test "$want_ntlm_wb" = "yes"; then
    AC_DEFINE(NTLM_WB_ENABLED, 1,
      [Define to enable NTLM delegation to winbind's ntlm_auth helper.])
    AC_DEFINE_UNQUOTED(NTLM_WB_FILE, "$want_ntlm_wb_file",
      [Define absolute filename for winbind's ntlm_auth helper.])
    NTLM_WB_ENABLED=1
  fi
])

dnl CURL_CHECK_OPTION_ECH
dnl -----------------------------------------------------
dnl Verify whether configure has been invoked with option
dnl --enable-ech or --disable-ech, and set
dnl shell variable want_ech as appropriate.

AC_DEFUN([CURL_CHECK_OPTION_ECH], [
  AC_MSG_CHECKING([whether to enable ECH support])
  OPT_ECH="default"
  AC_ARG_ENABLE(ech,
AS_HELP_STRING([--enable-ech],[Enable ECH support])
AS_HELP_STRING([--disable-ech],[Disable ECH support]),
  OPT_ECH=$enableval)
  case "$OPT_ECH" in
    no)
      dnl --disable-ech option used
      want_ech="no"
      curl_ech_msg="no      (--enable-ech)"
      AC_MSG_RESULT([no])
      ;;
    default)
      dnl configure option not specified
      want_ech="no"
      curl_ech_msg="no      (--enable-ech)"
      AC_MSG_RESULT([no])
      ;;
    *)
      dnl --enable-ech option used
      want_ech="yes"
      curl_ech_msg="enabled (--disable-ech)"
      experimental="ech"
      AC_MSG_RESULT([yes])
      ;;
  esac
])
