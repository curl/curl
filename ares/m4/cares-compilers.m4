#***************************************************************************
# $Id$
#
# Copyright (C) 2008 by Daniel Stenberg et al
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted, provided
# that the above copyright notice appear in all copies and that both that
# copyright notice and this permission notice appear in supporting
# documentation, and that the name of M.I.T. not be used in advertising or
# publicity pertaining to distribution of the software without specific,
# written prior permission.  M.I.T. makes no representations about the
# suitability of this software for any purpose.  It is provided "as is"
# without express or implied warranty.
#
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 2


dnl CARES_CHECK_COMPILER
dnl -------------------------------------------------
dnl Verify if the C compiler being used is known.

AC_DEFUN([CARES_CHECK_COMPILER], [
  #
  compiler_id="unknown"
  compiler_num="0"
  #
  CARES_CHECK_COMPILER_DEC
  CARES_CHECK_COMPILER_IBM
  CARES_CHECK_COMPILER_INTEL
  CARES_CHECK_COMPILER_GNU
  #
])


dnl CARES_CHECK_COMPILER_DEC
dnl -------------------------------------------------
dnl Verify if the C compiler being used is DEC's.

AC_DEFUN([CARES_CHECK_COMPILER_DEC], [
  AC_MSG_CHECKING([whether we are using the DEC/Compaq C compiler])
  CURL_CHECK_DEF([__DECC], [], [silent])
  CURL_CHECK_DEF([__DECC_VER], [], [silent])
  if test "$curl_cv_have_def___DECC" = "yes" &&
    test "$curl_cv_have_def___DECC_VER" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="DECC"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_GNU
dnl -------------------------------------------------
dnl Verify if the C compiler being used is GNU's.

AC_DEFUN([CARES_CHECK_COMPILER_GNU], [
  AC_REQUIRE([CARES_CHECK_COMPILER_INTEL])dnl
  #
  AC_MSG_CHECKING([whether we are using the GNU C compiler])
  CURL_CHECK_DEF([__GNUC__], [], [silent])
  if test "$curl_cv_have_def___GNUC__" = "yes" &&
    test "$compiler_id" = "unknown"; then
    AC_MSG_RESULT([yes])
    compiler_id="GNUC"
    gccver=`$CC -dumpversion`
    gccvhi=`echo $gccver | cut -d . -f1`
    gccvlo=`echo $gccver | cut -d . -f2`
    compiler_num=`(expr $gccvhi "*" 100 + $gccvlo) 2>/dev/null`
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_IBM
dnl -------------------------------------------------
dnl Verify if the C compiler being used is IBM's.

AC_DEFUN([CARES_CHECK_COMPILER_IBM], [
  AC_MSG_CHECKING([whether we are using the IBM C compiler])
  CURL_CHECK_DEF([__IBMC__], [], [silent])
  if test "$curl_cv_have_def___IBMC__" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="IBMC"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_INTEL
dnl -------------------------------------------------
dnl Verify if the C compiler being used is Intel's.

AC_DEFUN([CARES_CHECK_COMPILER_INTEL], [
  AC_BEFORE([$0],[CARES_CHECK_COMPILER_GNU])dnl
  AC_MSG_CHECKING([whether we are using the Intel C compiler])
  CURL_CHECK_DEF([__INTEL_COMPILER], [], [silent])
  if test "$curl_cv_have_def___INTEL_COMPILER" = "yes"; then
    AC_MSG_RESULT([yes])
    CURL_CHECK_DEF([__unix__], [], [silent])
    if test "$curl_cv_have_def___unix__" = "yes"; then
      compiler_id="ICC_unix"
    else
      compiler_id="ICC_windows"
    fi
    compiler_num="$curl_cv_def___INTEL_COMPILER"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_PROCESS_CC_BASIC_OPTS
dnl -------------------------------------------------
dnl Sets compiler options/flags which are independant
dnl of configure's debug or warnings options.

AC_DEFUN([CARES_PROCESS_CC_BASIC_OPTS], [
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" = "DECC"; then
    dnl Select strict ANSI C compiler mode
    CFLAGS="$CFLAGS -std1"
    dnl Turn off optimizer ANSI C aliasing rules
    CFLAGS="$CFLAGS -noansi_alias"
    dnl Generate warnings for missing function prototypes
    CFLAGS="$CFLAGS -warnprotos"
    dnl Change some warnings into fatal errors
    CFLAGS="$CFLAGS -msg_fatal toofewargs,toomanyargs"
  fi
  #
  if test "$compiler_id" = "IBMC"; then
    dnl Ensure that compiler optimizations are always thread-safe.
    CFLAGS="$CFLAGS -qthreaded"
    dnl Disable type based strict aliasing optimizations, using worst
    dnl case aliasing assumptions when compiling. Type based aliasing
    dnl would restrict the lvalues that could be safely used to access
    dnl a data object.
    CFLAGS="$CFLAGS -qnoansialias"
    dnl Force compiler to stop after the compilation phase, without
    dnl generating an object code file when compilation has errors.
    CFLAGS="$CFLAGS -qhalt=e"
  fi
  #
  if test "$compiler_id" = "ICC_unix"; then
    dnl On unix this compiler uses gcc's header files, so
    dnl we select ANSI C89 dialect plus GNU extensions.
    CPPFLAGS="$CPPFLAGS -std=gnu89"
    dnl Change some warnings into errors
    dnl #140: too many arguments in function call
    dnl #147: declaration is incompatible with 'previous one'
    dnl #165: too few arguments in function call
    dnl #266: function declared implicitly
    CPPFLAGS="$CPPFLAGS -we 140,147,165,266"
    dnl Disable some remarks
    dnl #279: controlling expression is constant
    dnl #981: operands are evaluated in unspecified order
    dnl #1469: "cc" clobber ignored
    if test "$compiler_num" -lt "910"; then
      CPPFLAGS="$CPPFLAGS -wd 279"
    fi
    CPPFLAGS="$CPPFLAGS -wd 981,1469"
    dnl Disable use of ANSI C aliasing rules in optimizations
    CFLAGS="$CFLAGS -no-ansi-alias"
    dnl Disable floating point optimizations
    CFLAGS="$CFLAGS -fp-model precise"
  fi
])


dnl CARES_PROCESS_CC_DEBUG_OPTS
dnl -------------------------------------------------
dnl Sets compiler options/flags which depend on
dnl configure's debug given option.

AC_DEFUN([CARES_PROCESS_CC_DEBUG_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_DEBUG])dnl
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$want_debug" = "yes"; then
    CFLAGS="$CFLAGS -g"
  fi
  #
  if test "$want_debug" = "no"; then
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
  fi
  #
])


dnl CARES_PROCESS_CC_WARNING_OPTS
dnl -------------------------------------------------
dnl Sets compiler options/flags which depend on
dnl configure's warnings given option.

AC_DEFUN([CARES_PROCESS_CC_WARNING_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_WARNINGS])dnl
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" = "DECC"; then
    if test "$want_warnings" = "yes"; then
      dnl Select a higher warning level than default level2
      CFLAGS="$CFLAGS -msg_enable level3"
    fi
  fi
  #
  if test "$compiler_id" = "ICC_unix"; then
    if test "$want_warnings" = "yes"; then
      if test "$compiler_num" -gt "600"; then
        dnl Show errors, warnings, and remarks
        CPPFLAGS="$CPPFLAGS -Wall"
        dnl Perform extra compile-time code checking
        CPPFLAGS="$CPPFLAGS -Wcheck"
      fi
    fi
  fi
  #
  if test "$compiler_id" = "GNUC"; then
    #
    # FIXME: Some of these warnings should be changed into errors
    #        and moved to CARES-PROCESS-CC-BASIC-OPTS
    #
    if test "$want_warnings" = "yes"; then
      dnl this is a set of options we believe *ALL* gcc versions support:
      WARN="-W -Wall -Wwrite-strings -pedantic -Wpointer-arith -Wnested-externs -Winline -Wmissing-prototypes"
      dnl -Wcast-align is a bit too annoying on all gcc versions ;-)
      if test "$compiler_num" -ge "207"; then
        dnl gcc 2.7 or later
        WARN="$WARN -Wmissing-declarations"
      fi
      if test "$compiler_num" -gt "295"; then
        dnl only if the compiler is newer than 2.95 since we got lots of
        dnl "`_POSIX_C_SOURCE' is not defined" in system headers with
        dnl gcc 2.95.4 on FreeBSD 4.9!
        WARN="$WARN -Wundef -Wno-long-long -Wsign-compare -Wshadow -Wno-multichar"
      fi
      if test "$compiler_num" -ge "296"; then
        dnl gcc 2.96 or later
        WARN="$WARN -Wfloat-equal"
      fi
      if test "$compiler_num" -gt "296"; then
        dnl this option does not exist in 2.96
        WARN="$WARN -Wno-format-nonliteral"
      fi
      dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
      dnl on i686-Linux as it gives us heaps with false positives.
      dnl Also, on gcc 4.0.X it is totally unbearable and complains all
      dnl over making it unusable for generic purposes. Let's not use it.
      if test "$compiler_num" -ge "303"; then
        dnl gcc 3.3 and later
        WARN="$WARN -Wendif-labels -Wstrict-prototypes"
      fi
      if test "$compiler_num" -ge "304"; then
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
      CFLAGS="$CFLAGS $WARN"
      AC_MSG_NOTICE([Added this set of compiler options: $WARN])
    fi
  fi
  #
])


dnl CARES_PROCESS_DEBUG_BUILD_OPTS
dnl -------------------------------------------------
dnl Settings which depend on configure's debug given
dnl option, and further configure the build process.

AC_DEFUN([CARES_PROCESS_DEBUG_BUILD_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_DEBUG])dnl
  AC_BEFORE([$0],[AC_PROG_LIBTOOL])dnl
  #
  if test "$want_debug" = "yes"; then

    dnl when doing the debug stuff, use static library only
    AC_DISABLE_SHARED

    debugbuild="yes"

    dnl the entire --enable-debug is a hack that lives and runs on top of
    dnl libcurl stuff so this BUILDING_LIBCURL is not THAT much uglier
    AC_DEFINE(BUILDING_LIBCURL, 1, [when building as static part of libcurl])

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG -I$srcdir/../include"
  fi
  #
])


