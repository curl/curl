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
# serial 19


dnl CARES_CHECK_COMPILER
dnl -------------------------------------------------
dnl Verify if the C compiler being used is known.

AC_DEFUN([CARES_CHECK_COMPILER], [
  #
  compiler_id="unknown"
  compiler_num="0"
  #
  flags_dbg_all="unknown"
  flags_dbg_yes="unknown"
  flags_dbg_off="unknown"
  flags_opt_all="unknown"
  flags_opt_yes="unknown"
  flags_opt_off="unknown"
  #
  CARES_CHECK_COMPILER_DEC
  CARES_CHECK_COMPILER_HP
  CARES_CHECK_COMPILER_IBM
  CARES_CHECK_COMPILER_INTEL
  CARES_CHECK_COMPILER_GNU
  CARES_CHECK_COMPILER_SGI
  CARES_CHECK_COMPILER_SUN
  #
  if test "$compiler_id" = "unknown"; then
  cat <<_EOF 1>&2
***
*** Warning: This configure script does not have information about the
*** compiler you are using, relative to the flags required to enable or
*** disable generation of debug info, optimization options or warnings.
***
*** Whatever settings are present in CFLAGS will be used for this run.
***
*** If you wish to help the c-ares project to better support your compiler
*** you can report this and the required info on the c-ares development
*** mailing list: http://cool.haxx.se/mailman/listinfo/c-ares/
***
_EOF
  fi
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
    flags_dbg_all="-g -g0 -g1 -g2 -g3"
    flags_dbg_yes="-g2"
    flags_dbg_off="-g0"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -O4"
    flags_opt_yes="-O1"
    flags_opt_off="-O0"
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
    flags_dbg_all="-g -g0 -g1 -g2 -g3"
    flags_dbg_all="$flags_dbg_all -ggdb"
    flags_dbg_all="$flags_dbg_all -gstabs"
    flags_dbg_all="$flags_dbg_all -gstabs+"
    flags_dbg_all="$flags_dbg_all -gcoff"
    flags_dbg_all="$flags_dbg_all -gxcoff"
    flags_dbg_all="$flags_dbg_all -gdwarf-2"
    flags_dbg_all="$flags_dbg_all -gvms"
    flags_dbg_yes="-g"
    flags_dbg_off="-g0"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -Os"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_HP
dnl -------------------------------------------------
dnl Verify if the C compiler being used is HP's.

AC_DEFUN([CARES_CHECK_COMPILER_HP], [
  AC_MSG_CHECKING([whether we are using the HP C compiler])
  CURL_CHECK_DEF([__HP_cc], [], [silent])
  if test "$curl_cv_have_def___HP_cc" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="HPUXC"
    flags_dbg_all="-g -s"
    flags_dbg_yes="-g"
    flags_dbg_off="-s"
    flags_opt_all="-O +O0 +O1 +O2 +O3 +O4"
    flags_opt_yes="+O2"
    flags_opt_off="+O0"
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
    flags_dbg_all="-g -g0 -g1 -g2 -g3"
    flags_dbg_yes="-g"
    flags_dbg_off=""
    flags_opt_all="-O -O0 -O1 -O2 -O3 -O4 -O5"
    flags_opt_all="$flags_opt_all -qnooptimize"
    flags_opt_all="$flags_opt_all -qoptimize=0"
    flags_opt_all="$flags_opt_all -qoptimize=1"
    flags_opt_all="$flags_opt_all -qoptimize=2"
    flags_opt_all="$flags_opt_all -qoptimize=3"
    flags_opt_all="$flags_opt_all -qoptimize=4"
    flags_opt_all="$flags_opt_all -qoptimize=5"
    flags_opt_yes="-O2"
    flags_opt_off="-qnooptimize"
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
      flags_dbg_all="-g -g0"
      flags_dbg_yes="-g"
      flags_dbg_off="-g0"
      flags_opt_all="-O -O0 -O1 -O2 -O3 -Os"
      flags_opt_yes="-O2"
      flags_opt_off="-O0"
    else
      compiler_id="ICC_windows"
      flags_dbg_all="/ZI /Zi /zI /zi /ZD /Zd /zD /zd /Z7 /z7 /Oy /Oy-"
      flags_dbg_all="$flags_dbg_all /debug"
      flags_dbg_all="$flags_dbg_all /debug:none"
      flags_dbg_all="$flags_dbg_all /debug:minimal"
      flags_dbg_all="$flags_dbg_all /debug:partial"
      flags_dbg_all="$flags_dbg_all /debug:full"
      flags_dbg_all="$flags_dbg_all /debug:semantic_stepping"
      flags_dbg_all="$flags_dbg_all /debug:extended"
      flags_dbg_yes="/Zi /Oy-"
      flags_dbg_off="/debug:none /Oy-"
      flags_opt_all="/O /O0 /O1 /O2 /O3 /Od /Og /Og- /Oi /Oi-"
      flags_opt_yes="/O2"
      flags_opt_off="/Od"
    fi
    compiler_num="$curl_cv_def___INTEL_COMPILER"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_SGI
dnl -------------------------------------------------
dnl Verify if the C compiler being used is SGI's.

AC_DEFUN([CARES_CHECK_COMPILER_SGI], [
  AC_MSG_CHECKING([whether we are using the SGI C compiler])
  CURL_CHECK_DEF([__GNUC__], [], [silent])
  CURL_CHECK_DEF([__sgi], [], [silent])
  if test "$curl_cv_have_def___GNUC__" = "no" &&
    test "$curl_cv_have_def___sgi" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="SGIC"
    flags_dbg_all="-g -g0 -g1 -g2 -g3"
    flags_dbg_yes="-g"
    flags_dbg_off="-g0"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -Ofast"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CHECK_COMPILER_SUN
dnl -------------------------------------------------
dnl Verify if the C compiler being used is SUN's.

AC_DEFUN([CARES_CHECK_COMPILER_SUN], [
  AC_MSG_CHECKING([whether we are using the SUN C compiler])
  CURL_CHECK_DEF([__SUNPRO_C], [], [silent])
  if test "$curl_cv_have_def___SUNPRO_C" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="SUNC"
    flags_dbg_all="-g -s"
    flags_dbg_yes="-g"
    flags_dbg_off="-s"
    flags_opt_all="-O -xO -xO1 -xO2 -xO3 -xO4 -xO5"
    flags_opt_yes="-xO2"
    flags_opt_off=""
  else
    AC_MSG_RESULT([no])
  fi
])


dnl CARES_CONVERT_INCLUDE_TO_ISYSTEM
dnl -------------------------------------------------
dnl Changes standard include paths present in CFLAGS
dnl and CPPFLAGS into isystem include paths. This is
dnl done to prevent GNUC from generating warnings on
dnl headers from these locations, even though this is
dnl not reliable on ancient GNUC versions.

AC_DEFUN([CARES_CONVERT_INCLUDE_TO_ISYSTEM], [
  tmp_has_include="no"
  tmp_chg_FLAGS=$CFLAGS
  for word1 in $tmp_chg_FLAGS; do
    case "$word1" in
      -I*)
        tmp_has_include="yes"
        ;;
    esac
  done
  if test "$tmp_has_include" = "yes"; then
    tmp_chg_FLAGS=`echo $tmp_chg_FLAGS | sed 's/^-I/ -isystem /g'`
    tmp_chg_FLAGS=`echo $tmp_chg_FLAGS | sed 's/ -I/ -isystem /g'`
    CFLAGS=`eval echo $tmp_chg_FLAGS`
  fi
  tmp_has_include="no"
  tmp_chg_FLAGS=$CPPFLAGS
  for word1 in $tmp_chg_FLAGS; do
    case "$word1" in
      -I*)
        tmp_has_include="yes"
        ;;
    esac
  done
  if test "$tmp_has_include" = "yes"; then
    tmp_chg_FLAGS=`echo $tmp_chg_FLAGS | sed 's/^-I/ -isystem /g'`
    tmp_chg_FLAGS=`echo $tmp_chg_FLAGS | sed 's/ -I/ -isystem /g'`
    CPPFLAGS=`eval echo $tmp_chg_FLAGS`
  fi
])


dnl CARES_COMPILER_WORKS_IFELSE ([ACTION-IF-WORKS], [ACTION-IF-NOT-WORKS])
dnl -------------------------------------------------
dnl Verify if the C compiler seems to work with the
dnl settings that are 'active' at the time the test
dnl is performed.

AC_DEFUN([CARES_COMPILER_WORKS_IFELSE], [
  dnl compilation capability verification
  tmp_compiler_works="unknown"
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      int i = 1;
      return i;
    ]])
  ],[
    tmp_compiler_works="yes"
  ],[
    tmp_compiler_works="no"
    echo " " >&6
    sed 's/^/cc-fail> /' conftest.err >&6
    echo " " >&6
  ])
  dnl linking capability verification
  if test "$tmp_compiler_works" = "yes"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        int i = 1;
        return i;
      ]])
    ],[
      tmp_compiler_works="yes"
    ],[
      tmp_compiler_works="no"
      echo " " >&6
      sed 's/^/ln-fail> /' conftest.err >&6
      echo " " >&6
    ])
  fi
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tmp_compiler_works" = "yes"; then
    AC_RUN_IFELSE([
      AC_LANG_PROGRAM([[
#       ifdef __STDC__
#         include <stdlib.h>
#       endif
      ]],[[
        int i = 0;
        exit(i);
      ]])
    ],[
      tmp_compiler_works="yes"
    ],[
      tmp_compiler_works="no"
      echo " " >&6
      echo "rn-fail test program exited with status $ac_status" >&6
      echo " " >&6
    ])
  fi
  dnl branch upon test result
  if test "$tmp_compiler_works" = "yes"; then
  ifelse($1,,:,[$1])
  ifelse($2,,,[else
    $2])
  fi
])


dnl CARES_SET_COMPILER_BASIC_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which do not
dnl depend on configure's debug, optimize or warnings
dnl options.

AC_DEFUN([CARES_SET_COMPILER_BASIC_OPTS], [
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" != "unknown"; then
    #
    if test "$compiler_id" = "GNUC"; then
      CARES_CONVERT_INCLUDE_TO_ISYSTEM
    fi
    #
    tmp_save_CPPFLAGS="$CPPFLAGS"
    tmp_save_CFLAGS="$CFLAGS"
    tmp_CPPFLAGS=""
    tmp_CFLAGS=""
    #
    case "$compiler_id" in
        #
      DECC)
        #
        dnl Select strict ANSI C compiler mode
        tmp_CFLAGS="$tmp_CFLAGS -std1"
        dnl Turn off optimizer ANSI C aliasing rules
        tmp_CFLAGS="$tmp_CFLAGS -noansi_alias"
        dnl Generate warnings for missing function prototypes
        tmp_CFLAGS="$tmp_CFLAGS -warnprotos"
        dnl Change some warnings into fatal errors
        tmp_CFLAGS="$tmp_CFLAGS -msg_fatal toofewargs,toomanyargs"
        ;;
        #
      GNUC)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      HPUXC)
        #
        dnl Disallow run-time dereferencing of null pointers
        tmp_CFLAGS="$tmp_CFLAGS -z"
        dnl Disable some remarks
        dnl #4227: padding struct with n bytes to align member
        dnl #4255: padding size of struct with n bytes to alignment boundary
        tmp_CFLAGS="$tmp_CFLAGS +W 4227,4255"
        ;;
        #
      IBMC)
        #
        dnl Ensure that compiler optimizations are always thread-safe.
        tmp_CFLAGS="$tmp_CFLAGS -qthreaded"
        dnl Disable type based strict aliasing optimizations, using worst
        dnl case aliasing assumptions when compiling. Type based aliasing
        dnl would restrict the lvalues that could be safely used to access
        dnl a data object.
        tmp_CFLAGS="$tmp_CFLAGS -qnoansialias"
        dnl Force compiler to stop after the compilation phase, without
        dnl generating an object code file when compilation has errors.
        tmp_CFLAGS="$tmp_CFLAGS -qhalt=e"
        ;;
        #
      ICC_unix)
        #
        dnl On unix this compiler uses gcc's header files, so
        dnl we select ANSI C89 dialect plus GNU extensions.
        tmp_CPPFLAGS="$tmp_CPPFLAGS -std=gnu89"
        dnl Change some warnings into errors
        dnl #140: too many arguments in function call
        dnl #147: declaration is incompatible with 'previous one'
        dnl #165: too few arguments in function call
        dnl #266: function declared implicitly
        tmp_CPPFLAGS="$tmp_CPPFLAGS -we 140,147,165,266"
        dnl Disable some remarks
        dnl #279: controlling expression is constant
        dnl #981: operands are evaluated in unspecified order
        dnl #1469: "cc" clobber ignored
        tmp_CPPFLAGS="$tmp_CPPFLAGS -wd 279,981,1469"
        dnl Disable use of ANSI C aliasing rules in optimizations
        tmp_CFLAGS="$tmp_CFLAGS -no-ansi-alias"
        dnl Disable floating point optimizations
        tmp_CFLAGS="$tmp_CFLAGS -fp-model precise"
        ;;
        #
      ICC_windows)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SGIC)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SUNC)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
    esac
    #
    tmp_CPPFLAGS=`eval echo $tmp_CPPFLAGS`
    tmp_CFLAGS=`eval echo $tmp_CFLAGS`
    #
    if test ! -z "$tmp_CFLAGS" || test ! -z "$tmp_CPPFLAGS"; then
      AC_MSG_CHECKING([if compiler accepts some basic options])
      CPPFLAGS=`eval echo $tmp_save_CPPFLAGS $tmp_CPPFLAGS`
      CFLAGS=`eval echo $tmp_save_CFLAGS $tmp_CFLAGS`
      CARES_COMPILER_WORKS_IFELSE([
        AC_MSG_RESULT([yes])
        AC_MSG_NOTICE([compiler options added: $tmp_CFLAGS $tmp_CPPFLAGS])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([compiler options rejected: $tmp_CFLAGS $tmp_CPPFLAGS])
        dnl restore initial settings
        CPPFLAGS="$tmp_save_CPPFLAGS"
        CFLAGS="$tmp_save_CFLAGS"
      ])
    fi
    #
  fi
])


dnl CARES_SET_COMPILER_DEBUG_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which depend
dnl on configure's debug option.

AC_DEFUN([CARES_SET_COMPILER_DEBUG_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_DEBUG])dnl
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" != "unknown"; then
    #
    tmp_save_CFLAGS="$CFLAGS"
    tmp_save_CPPFLAGS="$CPPFLAGS"
    #
    tmp_options=""
    tmp_CFLAGS="$CFLAGS"
    tmp_CPPFLAGS="$CPPFLAGS"
    CARES_VAR_STRIP([tmp_CFLAGS],[$flags_dbg_all])
    CARES_VAR_STRIP([tmp_CPPFLAGS],[$flags_dbg_all])
    #
    if test "$want_debug" = "yes"; then
      AC_MSG_CHECKING([if compiler accepts debug enabling options])
      tmp_options="$flags_dbg_yes"
    fi
    if test "$want_debug" = "no"; then
      AC_MSG_CHECKING([if compiler accepts debug disabling options])
      tmp_options="$flags_dbg_off"
    fi
    #
    CPPFLAGS=`eval echo $tmp_CPPFLAGS`
    CFLAGS=`eval echo $tmp_CFLAGS $tmp_options`
    CARES_COMPILER_WORKS_IFELSE([
      AC_MSG_RESULT([yes])
      AC_MSG_NOTICE([compiler options added: $tmp_options])
    ],[
      AC_MSG_RESULT([no])
      AC_MSG_WARN([compiler options rejected: $tmp_options])
      dnl restore initial settings
      CPPFLAGS="$tmp_save_CPPFLAGS"
      CFLAGS="$tmp_save_CFLAGS"
    ])
    #
  fi
])


dnl CARES_SET_COMPILER_OPTIMIZE_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which depend
dnl on configure's optimize option.

AC_DEFUN([CARES_SET_COMPILER_OPTIMIZE_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_OPTIMIZE])dnl
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" != "unknown"; then
    #
    tmp_save_CFLAGS="$CFLAGS"
    tmp_save_CPPFLAGS="$CPPFLAGS"
    #
    tmp_options=""
    tmp_CFLAGS="$CFLAGS"
    tmp_CPPFLAGS="$CPPFLAGS"
    honor_optimize_option="yes"
    #
    dnl If optimization request setting has not been explicitly specified,
    dnl it has been derived from the debug setting and initially assumed.
    dnl This initially assumed optimizer setting will finally be ignored
    dnl if CFLAGS or CPPFLAGS already hold optimizer flags. This implies
    dnl that an initially assumed optimizer setting might not be honored.
    #
    if test "$want_optimize" = "assume_no" ||
       test "$want_optimize" = "assume_yes"; then
      AC_MSG_CHECKING([if compiler optimizer assumed setting might be used])
      CARES_VAR_MATCH_IFELSE([tmp_CFLAGS],[$flags_opt_all],[
        honor_optimize_option="no"
      ])
      CARES_VAR_MATCH_IFELSE([tmp_CPPFLAGS],[$flags_opt_all],[
        honor_optimize_option="no"
      ])
      AC_MSG_RESULT([$honor_optimize_option])
      if test "$honor_optimize_option" = "yes"; then
        if test "$want_optimize" = "assume_yes"; then
          want_optimize="yes"
        fi
        if test "$want_optimize" = "assume_no"; then
          want_optimize="no"
        fi
      fi
    fi
    #
    if test "$honor_optimize_option" = "yes"; then
      CARES_VAR_STRIP([tmp_CFLAGS],[$flags_opt_all])
      CARES_VAR_STRIP([tmp_CPPFLAGS],[$flags_opt_all])
      if test "$want_optimize" = "yes"; then
        AC_MSG_CHECKING([if compiler accepts optimizer enabling options])
        tmp_options="$flags_opt_yes"
      fi
      if test "$want_optimize" = "no"; then
        AC_MSG_CHECKING([if compiler accepts optimizer disabling options])
        tmp_options="$flags_opt_off"
      fi
      CPPFLAGS=`eval echo $tmp_CPPFLAGS`
      CFLAGS=`eval echo $tmp_CFLAGS $tmp_options`
      CARES_COMPILER_WORKS_IFELSE([
        AC_MSG_RESULT([yes])
        AC_MSG_NOTICE([compiler options added: $tmp_options])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([compiler options rejected: $tmp_options])
        dnl restore initial settings
        CPPFLAGS="$tmp_save_CPPFLAGS"
        CFLAGS="$tmp_save_CFLAGS"
      ])
    fi
    #
  fi
])


dnl CARES_SET_COMPILER_WARNING_OPTS
dnl -------------------------------------------------
dnl Sets compiler options/flags which depend on
dnl configure's warnings given option.

AC_DEFUN([CARES_SET_COMPILER_WARNING_OPTS], [
  AC_REQUIRE([CARES_CHECK_OPTION_WARNINGS])dnl
  AC_REQUIRE([CARES_CHECK_COMPILER])dnl
  #
  if test "$compiler_id" != "unknown"; then
    #
    tmp_save_CPPFLAGS="$CPPFLAGS"
    tmp_save_CFLAGS="$CFLAGS"
    tmp_CPPFLAGS=""
    tmp_CFLAGS=""
    #
    case "$compiler_id" in
        #
      DECC)
        #
        if test "$want_warnings" = "yes"; then
          dnl Select a higher warning level than default level2
          tmp_CFLAGS="$tmp_CFLAGS -msg_enable level3"
        fi
        ;;
        #
      GNUC)
        #
        if test "$want_warnings" = "yes"; then
          dnl Set of options we believe *ALL* gcc versions support:
          tmp_CFLAGS="$tmp_CFLAGS -pedantic -Wall -W -Winline -Wnested-externs"
          tmp_CFLAGS="$tmp_CFLAGS -Wmissing-prototypes -Wpointer-arith"
          tmp_CFLAGS="$tmp_CFLAGS -Wwrite-strings"
          dnl -Wcast-align is a bit too annoying on all gcc versions ;-)
          if test "$compiler_num" -ge "207"; then
            dnl gcc 2.7 or later
            tmp_CFLAGS="$tmp_CFLAGS -Wmissing-declarations"
          fi
          if test "$compiler_num" -gt "295"; then
            dnl only if the compiler is newer than 2.95 since we got lots of
            dnl "`_POSIX_C_SOURCE' is not defined" in system headers with
            dnl gcc 2.95.4 on FreeBSD 4.9!
            tmp_CFLAGS="$tmp_CFLAGS -Wno-long-long -Wno-multichar -Wshadow"
            tmp_CFLAGS="$tmp_CFLAGS -Wsign-compare -Wundef"
          fi
          if test "$compiler_num" -ge "296"; then
            dnl gcc 2.96 or later
            tmp_CFLAGS="$tmp_CFLAGS -Wfloat-equal"
          fi
          if test "$compiler_num" -gt "296"; then
            dnl this option does not exist in 2.96
            tmp_CFLAGS="$tmp_CFLAGS -Wno-format-nonliteral"
          fi
          dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
          dnl on i686-Linux as it gives us heaps with false positives.
          dnl Also, on gcc 4.0.X it is totally unbearable and complains all
          dnl over making it unusable for generic purposes. Let's not use it.
          if test "$compiler_num" -ge "303"; then
            dnl gcc 3.3 and later
            tmp_CFLAGS="$tmp_CFLAGS -Wendif-labels -Wstrict-prototypes"
          fi
          if test "$compiler_num" -ge "304"; then
            dnl gcc 3.4 and later
            tmp_CFLAGS="$tmp_CFLAGS -Wdeclaration-after-statement"
          fi
        fi
        ;;
        #
      HPUXC)
        #
        if test "$want_warnings" = "yes"; then
          dnl Issue all warnings
          dnl tmp_CFLAGS="$tmp_CFLAGS +w1"
          dnl Due to the HP-UX socklen_t issue it is insane to use the +w1
          dnl warning level. Until the issue is somehow fixed we will just
          dnl use the +w2 warning level.
          tmp_CFLAGS="$tmp_CFLAGS +w2"
        fi
        ;;
        #
      IBMC)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      ICC_unix)
        #
        if test "$want_warnings" = "yes"; then
          if test "$compiler_num" -gt "600"; then
            dnl Show errors, warnings, and remarks
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wall"
            dnl Perform extra compile-time code checking
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wcheck"
          fi
        fi
        ;;
        #
      ICC_windows)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SGIC)
        #
        if test "$want_warnings" = "yes"; then
          dnl Perform stricter semantic and lint-like checks
          tmp_CFLAGS="$tmp_CFLAGS -fullwarn"
          dnl Disable some remarks
          dnl #1209: controlling expression is constant
          tmp_CFLAGS="$tmp_CFLAGS -woff 1209"
        fi
        ;;
        #
      SUNC)
        #
        if test "$want_warnings" = "yes"; then
          dnl Perform stricter semantic and lint-like checks
          tmp_CFLAGS="$tmp_CFLAGS -v"
        fi
        ;;
        #
    esac
    #
    tmp_CPPFLAGS=`eval echo $tmp_CPPFLAGS`
    tmp_CFLAGS=`eval echo $tmp_CFLAGS`
    #
    if test ! -z "$tmp_CFLAGS" || test ! -z "$tmp_CPPFLAGS"; then
      AC_MSG_CHECKING([if compiler accepts strict warning options])
      CPPFLAGS=`eval echo $tmp_save_CPPFLAGS $tmp_CPPFLAGS`
      CFLAGS=`eval echo $tmp_save_CFLAGS $tmp_CFLAGS`
      CARES_COMPILER_WORKS_IFELSE([
        AC_MSG_RESULT([yes])
        AC_MSG_NOTICE([compiler options added: $tmp_CFLAGS $tmp_CPPFLAGS])
      ],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([compiler options rejected: $tmp_CFLAGS $tmp_CPPFLAGS])
        dnl restore initial settings
        CPPFLAGS="$tmp_save_CPPFLAGS"
        CFLAGS="$tmp_save_CFLAGS"
      ])
    fi
    #
  fi
])


dnl CARES_PROCESS_DEBUG_BUILD_OPTS
dnl -------------------------------------------------
dnl Settings which depend on configure's debug given
dnl option, and further configure the build process.
dnl Don't use this macro for compiler dependant stuff.

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

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG"

    dnl CHECKME: Do we still need so specify this include path here?
    CPPFLAGS="$CPPFLAGS -I$srcdir/../include"

  fi
  #
])


dnl CARES_CHECK_PROG_CC
dnl -------------------------------------------------
dnl Check for compiler program, preventing CFLAGS and
dnl CPPFLAGS from being unexpectedly changed.

AC_DEFUN([CARES_CHECK_PROG_CC], [
  ac_save_CFLAGS="$CFLAGS"
  ac_save_CPPFLAGS="$CPPFLAGS"
  AC_PROG_CC
  CFLAGS="$ac_save_CFLAGS"
  CPPFLAGS="$ac_save_CPPFLAGS"
])


dnl CARES_VAR_MATCH (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Verifies if shell variable VARNAME contains VALUE.
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. If at least
dnl one word of VALUE is present in VARNAME the match
dnl is considered positive, otherwise false.

AC_DEFUN([CARES_VAR_MATCH], [
  ac_var_match_word="no"
  for word1 in $[$1]; do
    for word2 in [$2]; do
      if test "$word1" = "$word2"; then
        ac_var_match_word="yes"
      fi
    done
  done
])


dnl CARES_VAR_MATCH_IFELSE (VARNAME, VALUE,
dnl                        [ACTION-IF-MATCH], [ACTION-IF-NOT-MATCH])
dnl -------------------------------------------------
dnl This performs a CURL_VAR_MATCH check and executes
dnl first branch if the match is positive, otherwise
dnl the second branch is executed.

AC_DEFUN([CARES_VAR_MATCH_IFELSE], [
  CARES_VAR_MATCH([$1],[$2])
  if test "$ac_var_match_word" = "yes"; then
  ifelse($3,,:,[$3])
  ifelse($4,,,[else
    $4])
  fi
])


dnl CARES_VAR_STRIP (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. Each word
dnl from VALUE is removed from VARNAME when present.

AC_DEFUN([CARES_VAR_STRIP], [
  ac_var_stripped=""
  for word1 in $[$1]; do
    ac_var_strip_word="no"
    for word2 in [$2]; do
      if test "$word1" = "$word2"; then
        ac_var_strip_word="yes"
      fi
    done
    if test "$ac_var_strip_word" = "no"; then
      ac_var_stripped="$ac_var_stripped $word1"
    fi
  done
  dnl squeeze whitespace out of result
  [$1]=`eval echo $ac_var_stripped`
])
