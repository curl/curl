#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 67


dnl FETCH_CHECK_COMPILER
dnl -------------------------------------------------
dnl Verify if the C compiler being used is known.

AC_DEFUN([FETCH_CHECK_COMPILER], [
  #
  compiler_id="unknown"
  compiler_ver=""
  compiler_num="0"
  #
  flags_dbg_yes="unknown"
  flags_opt_all="unknown"
  flags_opt_yes="unknown"
  flags_opt_off="unknown"
  #
  flags_prefer_cppflags="no"
  #
  FETCH_CHECK_COMPILER_DEC_C
  FETCH_CHECK_COMPILER_HPUX_C
  FETCH_CHECK_COMPILER_IBM_C
  FETCH_CHECK_COMPILER_INTEL_C
  FETCH_CHECK_COMPILER_CLANG
  FETCH_CHECK_COMPILER_GNU_C
  case $host in
    mips-sgi-irix*)
      FETCH_CHECK_COMPILER_SGI_MIPSPRO_C
      FETCH_CHECK_COMPILER_SGI_MIPS_C
    ;;
  esac
  FETCH_CHECK_COMPILER_SUNPRO_C
  FETCH_CHECK_COMPILER_TINY_C
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
*** If you wish to help the fetch project to better support your compiler
*** you can report this and the required info on the libfetch development
*** mailing list: https://lists.haxx.selistinfo/fetch-library/
***
_EOF
  fi
])


dnl FETCH_CHECK_COMPILER_CLANG
dnl -------------------------------------------------
dnl Verify if compiler being used is clang.

AC_DEFUN([FETCH_CHECK_COMPILER_CLANG], [
  AC_BEFORE([$0],[FETCH_CHECK_COMPILER_GNU_C])dnl
  AC_MSG_CHECKING([if compiler is clang])
  FETCH_CHECK_DEF([__clang__], [], [silent])
  if test "$fetch_cv_have_def___clang__" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_MSG_CHECKING([if compiler is xlclang])
    FETCH_CHECK_DEF([__ibmxl__], [], [silent])
    if test "$fetch_cv_have_def___ibmxl__" = "yes" ; then
      dnl IBM's almost-compatible clang version
      AC_MSG_RESULT([yes])
      compiler_id="XLCLANG"
    else
      AC_MSG_RESULT([no])
      compiler_id="CLANG"
    fi
    AC_MSG_CHECKING([if compiler is Apple clang])
    fullclangver=`$CC -v 2>&1 | grep version`
    if echo $fullclangver | grep 'Apple' >/dev/null; then
      AC_MSG_RESULT([yes])
      appleclang=1
      compiler_id="APPLECLANG"
    else
      AC_MSG_RESULT([no])
      appleclang=0
    fi
    AC_MSG_CHECKING([compiler version])
    clangver=`echo $fullclangver | grep "based on LLVM " | "$SED" 's/.*(based on LLVM \(@<:@0-9@:>@*\.@<:@0-9@:>@*\).*)/\1/'`
    if test -z "$clangver"; then
      clangver=`echo $fullclangver | "$SED" 's/.*version \(@<:@0-9@:>@*\.@<:@0-9@:>@*\).*/\1/'`
      oldapple=0
    else
      oldapple=1
    fi
    clangvhi=`echo $clangver | cut -d . -f1`
    clangvlo=`echo $clangver | cut -d . -f2`
    compiler_ver="$clangver"
    compiler_num=`(expr $clangvhi "*" 100 + $clangvlo) 2>/dev/null`
    if test "$appleclang" = '1' && test "$oldapple" = '0'; then
      dnl Starting with Xcode 7 / clang 3.7, Apple clang won't tell its upstream version
      if   test "$compiler_num" -ge '1300'; then compiler_num='1200'
      elif test "$compiler_num" -ge '1205'; then compiler_num='1101'
      elif test "$compiler_num" -ge '1204'; then compiler_num='1000'
      elif test "$compiler_num" -ge '1107'; then compiler_num='900'
      elif test "$compiler_num" -ge '1103'; then compiler_num='800'
      elif test "$compiler_num" -ge '1003'; then compiler_num='700'
      elif test "$compiler_num" -ge '1001'; then compiler_num='600'
      elif test "$compiler_num" -ge  '904'; then compiler_num='500'
      elif test "$compiler_num" -ge  '902'; then compiler_num='400'
      elif test "$compiler_num" -ge  '803'; then compiler_num='309'
      elif test "$compiler_num" -ge  '703'; then compiler_num='308'
      else                                       compiler_num='307'
      fi
    fi
    AC_MSG_RESULT([clang '$compiler_num' (raw: '$fullclangver' / '$clangver')])
    flags_dbg_yes="-g"
    flags_opt_all="-O -O0 -O1 -O2 -Os -O3 -O4"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_DEC_C
dnl -------------------------------------------------
dnl Verify if compiler being used is DEC C.

AC_DEFUN([FETCH_CHECK_COMPILER_DEC_C], [
  AC_MSG_CHECKING([if compiler is DEC/Compaq/HP C])
  FETCH_CHECK_DEF([__DECC], [], [silent])
  FETCH_CHECK_DEF([__DECC_VER], [], [silent])
  if test "$fetch_cv_have_def___DECC" = "yes" &&
     test "$fetch_cv_have_def___DECC_VER" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="DEC_C"
    flags_dbg_yes="-g2"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -O4"
    flags_opt_yes="-O1"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_GNU_C
dnl -------------------------------------------------
dnl Verify if compiler being used is GNU C
dnl
dnl $compiler_num will be set to MAJOR * 100 + MINOR for gcc less than version
dnl 7 and just $MAJOR * 100 for gcc version 7 and later.
dnl
dnl Examples:
dnl Version 1.2.3 => 102
dnl Version 2.95  => 295
dnl Version 4.7 =>   407
dnl Version 9.2.1 => 900
dnl
AC_DEFUN([FETCH_CHECK_COMPILER_GNU_C], [
  AC_REQUIRE([FETCH_CHECK_COMPILER_INTEL_C])dnl
  AC_REQUIRE([FETCH_CHECK_COMPILER_CLANG])dnl
  AC_MSG_CHECKING([if compiler is GNU C])
  FETCH_CHECK_DEF([__GNUC__], [], [silent])
  if test "$fetch_cv_have_def___GNUC__" = "yes" &&
    test "$compiler_id" = "unknown"; then
    AC_MSG_RESULT([yes])
    compiler_id="GNU_C"
    AC_MSG_CHECKING([compiler version])
    # strip '-suffix' parts, e.g. Ubuntu Windows cross-gcc returns '10-win32'
    gccver=`$CC -dumpversion | "$SED" 's/-.\{1,\}$//'`
    gccvhi=`echo $gccver | cut -d . -f1`
    if echo $gccver | grep -F '.' >/dev/null; then
      gccvlo=`echo $gccver | cut -d . -f2`
    else
      gccvlo="0"
    fi
    compiler_ver="$gccver"
    compiler_num=`(expr $gccvhi "*" 100 + $gccvlo) 2>/dev/null`
    AC_MSG_RESULT([gcc '$compiler_num' (raw: '$gccver')])
    flags_dbg_yes="-g"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -Os -Og -Ofast"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_HPUX_C
dnl -------------------------------------------------
dnl Verify if compiler being used is HP-UX C.

AC_DEFUN([FETCH_CHECK_COMPILER_HPUX_C], [
  AC_MSG_CHECKING([if compiler is HP-UX C])
  FETCH_CHECK_DEF([__HP_cc], [], [silent])
  if test "$fetch_cv_have_def___HP_cc" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="HP_UX_C"
    flags_dbg_yes="-g"
    flags_opt_all="-O +O0 +O1 +O2 +O3 +O4"
    flags_opt_yes="+O2"
    flags_opt_off="+O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_IBM_C
dnl -------------------------------------------------
dnl Verify if compiler being used is IBM C.

AC_DEFUN([FETCH_CHECK_COMPILER_IBM_C], [
  AC_MSG_CHECKING([if compiler is IBM C])
  FETCH_CHECK_DEF([__IBMC__], [], [silent])
  if test "$fetch_cv_have_def___IBMC__" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="IBM_C"
    flags_dbg_yes="-g"
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
    flags_prefer_cppflags="yes"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_INTEL_C
dnl -------------------------------------------------
dnl Verify if compiler being used is Intel C.

AC_DEFUN([FETCH_CHECK_COMPILER_INTEL_C], [
  AC_BEFORE([$0],[FETCH_CHECK_COMPILER_GNU_C])dnl
  AC_MSG_CHECKING([if compiler is Intel C])
  FETCH_CHECK_DEF([__INTEL_COMPILER], [], [silent])
  if test "$fetch_cv_have_def___INTEL_COMPILER" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_MSG_CHECKING([compiler version])
    compiler_num="$fetch_cv_def___INTEL_COMPILER"
    compiler_ver=`echo "$compiler_num" | cut -c -2 | $SED 's/^0//'`.`echo "$compiler_num" | cut -c 3-4 | $SED 's/^0//'`
    AC_MSG_RESULT([Intel C '$compiler_num'])
    FETCH_CHECK_DEF([__unix__], [], [silent])
    if test "$fetch_cv_have_def___unix__" = "yes"; then
      compiler_id="INTEL_UNIX_C"
      flags_dbg_yes="-g"
      flags_opt_all="-O -O0 -O1 -O2 -O3 -Os"
      flags_opt_yes="-O2"
      flags_opt_off="-O0"
    else
      compiler_id="INTEL_WINDOWS_C"
      flags_dbg_yes="/Zi /Oy-"
      flags_opt_all="/O /O0 /O1 /O2 /O3 /Od /Og /Og- /Oi /Oi-"
      flags_opt_yes="/O2"
      flags_opt_off="/Od"
    fi
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_SGI_MIPS_C
dnl -------------------------------------------------
dnl Verify if compiler being used is SGI MIPS C.

AC_DEFUN([FETCH_CHECK_COMPILER_SGI_MIPS_C], [
  AC_REQUIRE([FETCH_CHECK_COMPILER_SGI_MIPSPRO_C])dnl
  AC_MSG_CHECKING([if compiler is SGI MIPS C])
  FETCH_CHECK_DEF([__GNUC__], [], [silent])
  FETCH_CHECK_DEF([__sgi], [], [silent])
  if test "$fetch_cv_have_def___GNUC__" = "no" &&
    test "$fetch_cv_have_def___sgi" = "yes" &&
    test "$compiler_id" = "unknown"; then
    AC_MSG_RESULT([yes])
    compiler_id="SGI_MIPS_C"
    flags_dbg_yes="-g"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -Ofast"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_SGI_MIPSPRO_C
dnl -------------------------------------------------
dnl Verify if compiler being used is SGI MIPSpro C.

AC_DEFUN([FETCH_CHECK_COMPILER_SGI_MIPSPRO_C], [
  AC_BEFORE([$0],[FETCH_CHECK_COMPILER_SGI_MIPS_C])dnl
  AC_MSG_CHECKING([if compiler is SGI MIPSpro C])
  FETCH_CHECK_DEF([__GNUC__], [], [silent])
  FETCH_CHECK_DEF([_COMPILER_VERSION], [], [silent])
  FETCH_CHECK_DEF([_SGI_COMPILER_VERSION], [], [silent])
  if test "$fetch_cv_have_def___GNUC__" = "no" &&
    (test "$fetch_cv_have_def__SGI_COMPILER_VERSION" = "yes" ||
     test "$fetch_cv_have_def__COMPILER_VERSION" = "yes"); then
    AC_MSG_RESULT([yes])
    compiler_id="SGI_MIPSPRO_C"
    flags_dbg_yes="-g"
    flags_opt_all="-O -O0 -O1 -O2 -O3 -Ofast"
    flags_opt_yes="-O2"
    flags_opt_off="-O0"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_SUNPRO_C
dnl -------------------------------------------------
dnl Verify if compiler being used is SunPro C.

AC_DEFUN([FETCH_CHECK_COMPILER_SUNPRO_C], [
  AC_MSG_CHECKING([if compiler is SunPro C])
  FETCH_CHECK_DEF([__SUNPRO_C], [], [silent])
  if test "$fetch_cv_have_def___SUNPRO_C" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="SUNPRO_C"
    flags_dbg_yes="-g"
    flags_opt_all="-O -xO -xO1 -xO2 -xO3 -xO4 -xO5"
    flags_opt_yes="-xO2"
    flags_opt_off=""
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_TINY_C
dnl -------------------------------------------------
dnl Verify if compiler being used is Tiny C.

AC_DEFUN([FETCH_CHECK_COMPILER_TINY_C], [
  AC_MSG_CHECKING([if compiler is Tiny C])
  FETCH_CHECK_DEF([__TINYC__], [], [silent])
  if test "$fetch_cv_have_def___TINYC__" = "yes"; then
    AC_MSG_RESULT([yes])
    compiler_id="TINY_C"
    flags_dbg_yes="-g"
    flags_opt_all=""
    flags_opt_yes=""
    flags_opt_off=""
  else
    AC_MSG_RESULT([no])
  fi
])

dnl FETCH_CONVERT_INCLUDE_TO_ISYSTEM
dnl -------------------------------------------------
dnl Changes standard include paths present in CFLAGS
dnl and CPPFLAGS into isystem include paths. This is
dnl done to prevent GNUC from generating warnings on
dnl headers from these locations, although on ancient
dnl GNUC versions these warnings are not silenced.

AC_DEFUN([FETCH_CONVERT_INCLUDE_TO_ISYSTEM], [
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_MSG_CHECKING([convert -I options to -isystem])
  if test "$compiler_id" = "GNU_C" ||
    test "$compiler_id" = "CLANG" -o "$compiler_id" = "APPLECLANG"; then
    AC_MSG_RESULT([yes])
    tmp_has_include="no"
    tmp_chg_FLAGS="$CFLAGS"
    for word1 in $tmp_chg_FLAGS; do
      case "$word1" in
        -I*)
          tmp_has_include="yes"
          ;;
      esac
    done
    if test "$tmp_has_include" = "yes"; then
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/^-I/ -isystem /g'`
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/ -I/ -isystem /g'`
      CFLAGS="$tmp_chg_FLAGS"
      squeeze CFLAGS
    fi
    tmp_has_include="no"
    tmp_chg_FLAGS="$CPPFLAGS"
    for word1 in $tmp_chg_FLAGS; do
      case "$word1" in
        -I*)
          tmp_has_include="yes"
          ;;
      esac
    done
    if test "$tmp_has_include" = "yes"; then
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/^-I/ -isystem /g'`
      tmp_chg_FLAGS=`echo "$tmp_chg_FLAGS" | "$SED" 's/ -I/ -isystem /g'`
      CPPFLAGS="$tmp_chg_FLAGS"
      squeeze CPPFLAGS
    fi
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_COMPILER_WORKS_IFELSE ([ACTION-IF-WORKS], [ACTION-IF-NOT-WORKS])
dnl -------------------------------------------------
dnl Verify if the C compiler seems to work with the
dnl settings that are 'active' at the time the test
dnl is performed.

AC_DEFUN([FETCH_COMPILER_WORKS_IFELSE], [
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
    sed 's/^/cc-fail: /' conftest.err >&6
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
      sed 's/^/link-fail: /' conftest.err >&6
      echo " " >&6
    ])
  fi
  dnl only do runtime verification when not cross-compiling
  if test "x$cross_compiling" != "xyes" &&
    test "$tmp_compiler_works" = "yes"; then
    FETCH_RUN_IFELSE([
      AC_LANG_PROGRAM([[
        #ifdef __STDC__
        #  include <stdlib.h>
        #endif
      ]],[[
        int i = 0;
        exit(i);
      ]])
    ],[
      tmp_compiler_works="yes"
    ],[
      tmp_compiler_works="no"
      echo " " >&6
      echo "run-fail: test program exited with status $ac_status" >&6
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


dnl FETCH_SET_COMPILER_BASIC_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which do not
dnl depend on configure's debug, optimize or warnings
dnl options.

AC_DEFUN([FETCH_SET_COMPILER_BASIC_OPTS], [
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
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
      CLANG|APPLECLANG)
        #
        dnl Disable warnings for unused arguments, otherwise clang will
        dnl warn about compile-time arguments used during link-time, like
        dnl -O and -g and -pedantic.
        tmp_CFLAGS="$tmp_CFLAGS -Qunused-arguments"
        tmp_CFLAGS="$tmp_CFLAGS -Werror-implicit-function-declaration"
        ;;
        #
      DEC_C)
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
      GNU_C)
        #
        dnl turn implicit-function-declaration warning into error,
        dnl at least gcc 2.95 and later support this
        if test "$compiler_num" -ge "295"; then
          tmp_CFLAGS="$tmp_CFLAGS -Werror-implicit-function-declaration"
        fi
        ;;
        #
      HP_UX_C)
        #
        dnl Disallow run-time dereferencing of null pointers
        tmp_CFLAGS="$tmp_CFLAGS -z"
        dnl Disable some remarks
        dnl #4227: padding struct with n bytes to align member
        dnl #4255: padding size of struct with n bytes to alignment boundary
        tmp_CFLAGS="$tmp_CFLAGS +W 4227,4255"
        ;;
        #
      IBM_C)
        #
        dnl Ensure that compiler optimizations are always thread-safe.
        tmp_CPPFLAGS="$tmp_CPPFLAGS -qthreaded"
        dnl Disable type based strict aliasing optimizations, using worst
        dnl case aliasing assumptions when compiling. Type based aliasing
        dnl would restrict the lvalues that could be safely used to access
        dnl a data object.
        tmp_CPPFLAGS="$tmp_CPPFLAGS -qnoansialias"
        dnl Force compiler to stop after the compilation phase, without
        dnl generating an object code file when compilation has errors.
        tmp_CPPFLAGS="$tmp_CPPFLAGS -qhalt=e"
        ;;
        #
      INTEL_UNIX_C)
        #
        dnl On Unix this compiler uses gcc's header files, so
        dnl we select ANSI C89 dialect plus GNU extensions.
        tmp_CFLAGS="$tmp_CFLAGS -std=gnu89"
        dnl Change some warnings into errors
        dnl #140: too many arguments in function call
        dnl #147: declaration is incompatible with 'previous one'
        dnl #165: too few arguments in function call
        dnl #266: function declared implicitly
        tmp_CPPFLAGS="$tmp_CPPFLAGS -diag-error 140,147,165,266"
        dnl Disable some remarks
        dnl #279: controlling expression is constant
        dnl #981: operands are evaluated in unspecified order
        dnl #1025: zero extending result of unary operation
        dnl #1469: "cc" clobber ignored
        dnl #2259: non-pointer conversion from X to Y may lose significant bits
        tmp_CPPFLAGS="$tmp_CPPFLAGS -diag-disable 279,981,1025,1469,2259"
        ;;
        #
      INTEL_WINDOWS_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SGI_MIPS_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SGI_MIPSPRO_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SUNPRO_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      TINY_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
    esac
    #
    squeeze tmp_CPPFLAGS
    squeeze tmp_CFLAGS
    #
    if test ! -z "$tmp_CFLAGS" || test ! -z "$tmp_CPPFLAGS"; then
      AC_MSG_CHECKING([if compiler accepts some basic options])
      CPPFLAGS="$tmp_save_CPPFLAGS $tmp_CPPFLAGS"
      CFLAGS="$tmp_save_CFLAGS $tmp_CFLAGS"
      squeeze CPPFLAGS
      squeeze CFLAGS
      FETCH_COMPILER_WORKS_IFELSE([
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


dnl FETCH_SET_COMPILER_DEBUG_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which depend
dnl on configure's debug option.

AC_DEFUN([FETCH_SET_COMPILER_DEBUG_OPTS], [
  AC_REQUIRE([FETCH_CHECK_OPTION_DEBUG])dnl
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
  #
  if test "$compiler_id" != "unknown"; then
    #
    tmp_save_CFLAGS="$CFLAGS"
    tmp_save_CPPFLAGS="$CPPFLAGS"
    #
    tmp_options=""
    tmp_CFLAGS="$CFLAGS"
    tmp_CPPFLAGS="$CPPFLAGS"
    #
    if test "$want_debug" = "yes"; then
      AC_MSG_CHECKING([if compiler accepts debug enabling options])
      tmp_options="$flags_dbg_yes"
    fi
    #
    if test "$flags_prefer_cppflags" = "yes"; then
      CPPFLAGS="$tmp_CPPFLAGS $tmp_options"
      CFLAGS="$tmp_CFLAGS"
    else
      CPPFLAGS="$tmp_CPPFLAGS"
      CFLAGS="$tmp_CFLAGS $tmp_options"
    fi
    squeeze CPPFLAGS
    squeeze CFLAGS
  fi
])


dnl FETCH_SET_COMPILER_OPTIMIZE_OPTS
dnl -------------------------------------------------
dnl Sets compiler specific options/flags which depend
dnl on configure's optimize option.

AC_DEFUN([FETCH_SET_COMPILER_OPTIMIZE_OPTS], [
  AC_REQUIRE([FETCH_CHECK_OPTION_OPTIMIZE])dnl
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
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
      FETCH_VAR_MATCH_IFELSE([tmp_CFLAGS],[$flags_opt_all],[
        honor_optimize_option="no"
      ])
      FETCH_VAR_MATCH_IFELSE([tmp_CPPFLAGS],[$flags_opt_all],[
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
      FETCH_VAR_STRIP([tmp_CFLAGS],[$flags_opt_all])
      FETCH_VAR_STRIP([tmp_CPPFLAGS],[$flags_opt_all])
      if test "$want_optimize" = "yes"; then
        AC_MSG_CHECKING([if compiler accepts optimizer enabling options])
        tmp_options="$flags_opt_yes"
      fi
      if test "$want_optimize" = "no"; then
        AC_MSG_CHECKING([if compiler accepts optimizer disabling options])
        tmp_options="$flags_opt_off"
      fi
      if test "$flags_prefer_cppflags" = "yes"; then
        CPPFLAGS="$tmp_CPPFLAGS $tmp_options"
        CFLAGS="$tmp_CFLAGS"
      else
        CPPFLAGS="$tmp_CPPFLAGS"
        CFLAGS="$tmp_CFLAGS $tmp_options"
      fi
      squeeze CPPFLAGS
      squeeze CFLAGS
      FETCH_COMPILER_WORKS_IFELSE([
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


dnl FETCH_SET_COMPILER_WARNING_OPTS
dnl -------------------------------------------------
dnl Sets compiler options/flags which depend on
dnl configure's warnings given option.

AC_DEFUN([FETCH_SET_COMPILER_WARNING_OPTS], [
  AC_REQUIRE([FETCH_CHECK_OPTION_WARNINGS])dnl
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
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
      CLANG|APPLECLANG)
        #
        if test "$want_warnings" = "yes"; then
          tmp_CFLAGS="$tmp_CFLAGS -pedantic"
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [all extra])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [pointer-arith write-strings])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [shadow])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [nested-externs])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-declarations])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-prototypes])
          tmp_CFLAGS="$tmp_CFLAGS -Wno-long-long"
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [float-equal])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [sign-compare])
          tmp_CFLAGS="$tmp_CFLAGS -Wno-multichar"
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [undef])
          tmp_CFLAGS="$tmp_CFLAGS -Wno-format-nonliteral"
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [endif-labels strict-prototypes])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [declaration-after-statement])
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [cast-align])
          tmp_CFLAGS="$tmp_CFLAGS -Wno-system-headers"
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [shorten-64-to-32])
          #
          dnl Only clang 1.1 or later
          if test "$compiler_num" -ge "101"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused])
          fi
          #
          dnl Only clang 2.7 or later
          if test "$compiler_num" -ge "207"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [address])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [attributes])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [bad-function-cast])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [conversion])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [div-by-zero format-security])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [empty-body])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-field-initializers])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-noreturn])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [old-style-definition])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [redundant-decls])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [switch-enum])      # Not used because this basically disallows default case
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [type-limits])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused-macros])    # Not practical
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unreachable-code unused-parameter])
          fi
          #
          dnl Only clang 2.8 or later
          if test "$compiler_num" -ge "208"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [ignored-qualifiers])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [vla])
          fi
          #
          dnl Only clang 2.9 or later
          if test "$compiler_num" -ge "209"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [sign-conversion])
            tmp_CFLAGS="$tmp_CFLAGS -Wno-error=sign-conversion"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [shift-sign-overflow])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [padded])  # Not used because we cannot change public structs
          fi
          #
          dnl Only clang 3.0 or later
          if test "$compiler_num" -ge "300"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [language-extension-token])
            tmp_CFLAGS="$tmp_CFLAGS -Wformat=2"
          fi
          #
          dnl Only clang 3.2 or later
          if test "$compiler_num" -ge "302"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [enum-conversion])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [sometimes-uninitialized])
            case $host_os in
              cygwin* | mingw*)
                dnl skip missing-variable-declarations warnings for Cygwin and
                dnl MinGW because the libtool wrapper executable causes them
                ;;
              *)
                FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-variable-declarations])
                ;;
            esac
          fi
          #
          dnl Only clang 3.4 or later
          if test "$compiler_num" -ge "304"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [header-guard])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused-const-variable])
          fi
          #
          dnl Only clang 3.5 or later
          if test "$compiler_num" -ge "305"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [pragmas])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unreachable-code-break])  # Not used: Silent in "unity" builds
          fi
          #
          dnl Only clang 3.6 or later
          if test "$compiler_num" -ge "306"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [double-promotion])
          fi
          #
          dnl Only clang 3.9 or later
          if test "$compiler_num" -ge "309"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [comma])
            # avoid the varargs warning, fixed in 4.0
            # https://bugs.llvm.org/show_bug.cgi?id=29140
            if test "$compiler_num" -lt "400"; then
              tmp_CFLAGS="$tmp_CFLAGS -Wno-varargs"
            fi
          fi
          dnl clang 7 or later
          if test "$compiler_num" -ge "700"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [assign-enum])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [extra-semi-stmt])
          fi
          dnl clang 10 or later
          if test "$compiler_num" -ge "1000"; then
            tmp_CFLAGS="$tmp_CFLAGS -Wimplicit-fallthrough"  # we have silencing markup for clang 10.0 and above only
          fi
        fi
        ;;
        #
      DEC_C)
        #
        if test "$want_warnings" = "yes"; then
          dnl Select a higher warning level than default level2
          tmp_CFLAGS="$tmp_CFLAGS -msg_enable level3"
        fi
        ;;
        #
      GNU_C)
        #
        if test "$want_warnings" = "yes"; then
          #
          dnl Do not enable -pedantic when cross-compiling with a gcc older
          dnl than 3.0, to avoid warnings from third party system headers.
          if test "x$cross_compiling" != "xyes" ||
            test "$compiler_num" -ge "300"; then
            tmp_CFLAGS="$tmp_CFLAGS -pedantic"
          fi
          #
          dnl Set of options we believe *ALL* gcc versions support:
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [all])
          tmp_CFLAGS="$tmp_CFLAGS -W"
          #
          dnl Only gcc 1.4 or later
          if test "$compiler_num" -ge "104"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [pointer-arith write-strings])
            dnl If not cross-compiling with a gcc older than 3.0
            if test "x$cross_compiling" != "xyes" ||
              test "$compiler_num" -ge "300"; then
              FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused shadow])
            fi
          fi
          #
          dnl Only gcc 2.7 or later
          if test "$compiler_num" -ge "207"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [nested-externs])
            dnl If not cross-compiling with a gcc older than 3.0
            if test "x$cross_compiling" != "xyes" ||
              test "$compiler_num" -ge "300"; then
              FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-declarations])
              FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-prototypes])
            fi
          fi
          #
          dnl Only gcc 2.95 or later
          if test "$compiler_num" -ge "295"; then
            tmp_CFLAGS="$tmp_CFLAGS -Wno-long-long"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [bad-function-cast])
          fi
          #
          dnl Only gcc 2.96 or later
          if test "$compiler_num" -ge "296"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [float-equal])
            tmp_CFLAGS="$tmp_CFLAGS -Wno-multichar"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [sign-compare])
            dnl -Wundef used only if gcc is 2.96 or later since we get
            dnl lots of "`_POSIX_C_SOURCE' is not defined" in system
            dnl headers with gcc 2.95.4 on FreeBSD 4.9
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [undef])
          fi
          #
          dnl Only gcc 2.97 or later
          if test "$compiler_num" -ge "297"; then
            tmp_CFLAGS="$tmp_CFLAGS -Wno-format-nonliteral"
          fi
          #
          dnl Only gcc 3.0 or later
          if test "$compiler_num" -ge "300"; then
            dnl -Wunreachable-code seems totally unreliable on my gcc 3.3.2 on
            dnl on i686-Linux as it gives us heaps with false positives.
            dnl Also, on gcc 4.0.X it is totally unbearable and complains all
            dnl over making it unusable for generic purposes. Let's not use it.
            tmp_CFLAGS="$tmp_CFLAGS"
          fi
          #
          dnl Only gcc 3.3 or later
          if test "$compiler_num" -ge "303"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [endif-labels strict-prototypes])
          fi
          #
          dnl Only gcc 3.4 or later
          if test "$compiler_num" -ge "304"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [declaration-after-statement])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [old-style-definition])
          fi
          #
          dnl Only gcc 4.0 or later
          if test "$compiler_num" -ge "400"; then
            tmp_CFLAGS="$tmp_CFLAGS -Wstrict-aliasing=3"
          fi
          #
          dnl Only gcc 4.1 or later
          if test "$compiler_num" -ge "401"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [attributes])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [div-by-zero format-security])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-field-initializers])
            case $host in
              *-*-msys*)
                ;;
              *)
                FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-noreturn])  # Seen to clash with libtool-generated stub code
                ;;
            esac
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unreachable-code unused-parameter])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [padded])           # Not used because we cannot change public structs
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [pragmas])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [redundant-decls])
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [switch-enum])      # Not used because this basically disallows default case
          # FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused-macros])    # Not practical
          fi
          #
          dnl Only gcc 4.2 or later
          if test "$compiler_num" -ge "402"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [cast-align])
          fi
          #
          dnl Only gcc 4.3 or later
          if test "$compiler_num" -ge "403"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [address])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [type-limits old-style-declaration])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [missing-parameter-type empty-body])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [clobbered ignored-qualifiers])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [conversion])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [sign-conversion])
            tmp_CFLAGS="$tmp_CFLAGS -Wno-error=sign-conversion"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [vla])
            dnl required for -Warray-bounds, included in -Wall
            tmp_CFLAGS="$tmp_CFLAGS -ftree-vrp"
          fi
          #
          dnl Only gcc 4.5 or later
          if test "$compiler_num" -ge "405"; then
            dnl Only Windows targets
            if test "$fetch_cv_native_windows" = "yes"; then
              tmp_CFLAGS="$tmp_CFLAGS -Wno-pedantic-ms-format"
            fi
            case $host_os in
              cygwin*)
                dnl Silence warning in 'lt_fatal' libtool function
                tmp_CFLAGS="$tmp_CFLAGS -Wno-suggest-attribute=noreturn"
                ;;
            esac
          fi
          #
          dnl Only gcc 4.6 or later
          if test "$compiler_num" -ge "406"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [double-promotion])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [trampolines])
          fi
          #
          dnl only gcc 4.8 or later
          if test "$compiler_num" -ge "408"; then
            tmp_CFLAGS="$tmp_CFLAGS -Wformat=2"
          fi
          #
          dnl Only gcc 5 or later
          if test "$compiler_num" -ge "500"; then
            tmp_CFLAGS="$tmp_CFLAGS -Warray-bounds=2"
          fi
          #
          dnl Only gcc 6 or later
          if test "$compiler_num" -ge "600"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [shift-negative-value])
            tmp_CFLAGS="$tmp_CFLAGS -Wshift-overflow=2"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [null-dereference])
            tmp_CFLAGS="$tmp_CFLAGS -fdelete-null-pointer-checks"
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [duplicated-cond])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unused-const-variable])
          fi
          #
          dnl Only gcc 7 or later
          if test "$compiler_num" -ge "700"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [duplicated-branches])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [restrict])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [alloc-zero])
            tmp_CFLAGS="$tmp_CFLAGS -Wformat-truncation=2"
            tmp_CFLAGS="$tmp_CFLAGS -Wimplicit-fallthrough"
          fi
          #
          dnl Only gcc 10 or later
          if test "$compiler_num" -ge "1000"; then
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [arith-conversion])
            FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [enum-conversion])
          fi
          #
        fi
        #
        dnl Do not issue warnings for code in system include paths.
        if test "$compiler_num" -ge "300"; then
          tmp_CFLAGS="$tmp_CFLAGS -Wno-system-headers"
        else
          dnl When cross-compiling with a gcc older than 3.0, disable
          dnl some warnings triggered on third party system headers.
          if test "x$cross_compiling" = "xyes"; then
            if test "$compiler_num" -ge "104"; then
              dnl gcc 1.4 or later
              tmp_CFLAGS="$tmp_CFLAGS -Wno-unused -Wno-shadow"
            fi
            if test "$compiler_num" -ge "207"; then
              dnl gcc 2.7 or later
              tmp_CFLAGS="$tmp_CFLAGS -Wno-missing-declarations"
              tmp_CFLAGS="$tmp_CFLAGS -Wno-missing-prototypes"
            fi
          fi
        fi
        if test "$compiler_num" -lt "405"; then
          dnl Avoid false positives
          tmp_CFLAGS="$tmp_CFLAGS -Wno-shadow"
          tmp_CFLAGS="$tmp_CFLAGS -Wno-unreachable-code"
        fi
        if test "$compiler_num" -ge "402" -a "$compiler_num" -lt "406"; then
          dnl GCC <4.6 do not support #pragma to suppress warnings locally. Disable globally instead.
          tmp_CFLAGS="$tmp_CFLAGS -Wno-overlength-strings"
        fi
        if test "$compiler_num" -ge "400" -a "$compiler_num" -lt "407"; then
          dnl https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84685
          tmp_CFLAGS="$tmp_CFLAGS -Wno-missing-field-initializers"
        fi
        if test "$compiler_num" -ge "403" -a "$compiler_num" -lt "408"; then
          dnl Avoid false positives
          tmp_CFLAGS="$tmp_CFLAGS -Wno-type-limits"
        fi
        ;;
        #
      HP_UX_C)
        #
        if test "$want_warnings" = "yes"; then
          dnl Issue all warnings
          tmp_CFLAGS="$tmp_CFLAGS +w1"
        fi
        ;;
        #
      IBM_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      INTEL_UNIX_C)
        #
        if test "$want_warnings" = "yes"; then
          if test "$compiler_num" -gt "600"; then
            dnl Show errors, warnings, and remarks
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wall -w2"
            dnl Perform extra compile-time code checking
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wcheck"
            dnl Warn on nested comments
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wcomment"
            dnl Show warnings relative to deprecated features
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wdeprecated"
            dnl Enable warnings for missing prototypes
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wmissing-prototypes"
            dnl Enable warnings for 64-bit portability issues
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wp64"
            dnl Enable warnings for questionable pointer arithmetic
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wpointer-arith"
            dnl Check for function return typw issues
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wreturn-type"
            dnl Warn on variable declarations hiding a previous one
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wshadow"
            dnl Warn when a variable is used before initialized
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wuninitialized"
            dnl Warn if a declared function is not used
            tmp_CPPFLAGS="$tmp_CPPFLAGS -Wunused-function"
          fi
        fi
        dnl Disable using EBP register in optimizations
        tmp_CFLAGS="$tmp_CFLAGS -fno-omit-frame-pointer"
        dnl Disable use of ANSI C aliasing rules in optimizations
        tmp_CFLAGS="$tmp_CFLAGS -fno-strict-aliasing"
        dnl Value-safe optimizations on floating-point data
        tmp_CFLAGS="$tmp_CFLAGS -fp-model precise"
        ;;
        #
      INTEL_WINDOWS_C)
        #
        dnl Placeholder
        tmp_CFLAGS="$tmp_CFLAGS"
        ;;
        #
      SGI_MIPS_C)
        #
        if test "$want_warnings" = "yes"; then
          dnl Perform stricter semantic and lint-like checks
          tmp_CFLAGS="$tmp_CFLAGS -fullwarn"
        fi
        ;;
        #
      SGI_MIPSPRO_C)
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
      SUNPRO_C)
        #
        if test "$want_warnings" = "yes"; then
          dnl Perform stricter semantic and lint-like checks
          tmp_CFLAGS="$tmp_CFLAGS -v"
        fi
        ;;
        #
      TINY_C)
        #
        if test "$want_warnings" = "yes"; then
          dnl Activate all warnings
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [all])
          dnl Make string constants be of type const char *
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [write-strings])
          dnl Warn use of unsupported GCC features ignored by TCC
          FETCH_ADD_COMPILER_WARNINGS([tmp_CFLAGS], [unsupported])
        fi
        ;;
        #
    esac
    #
    squeeze tmp_CPPFLAGS
    squeeze tmp_CFLAGS
    #
    if test ! -z "$tmp_CFLAGS" || test ! -z "$tmp_CPPFLAGS"; then
      AC_MSG_CHECKING([if compiler accepts strict warning options])
      CPPFLAGS="$tmp_save_CPPFLAGS $tmp_CPPFLAGS"
      CFLAGS="$tmp_save_CFLAGS $tmp_CFLAGS"
      squeeze CPPFLAGS
      squeeze CFLAGS
      FETCH_COMPILER_WORKS_IFELSE([
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


dnl FETCH_SHFUNC_SQUEEZE
dnl -------------------------------------------------
dnl Declares a shell function squeeze() which removes
dnl redundant whitespace out of a shell variable.

AC_DEFUN([FETCH_SHFUNC_SQUEEZE], [
squeeze() {
  _sqz_result=""
  eval _sqz_input=\[$][$]1
  for _sqz_token in $_sqz_input; do
    if test -z "$_sqz_result"; then
      _sqz_result="$_sqz_token"
    else
      _sqz_result="$_sqz_result $_sqz_token"
    fi
  done
  eval [$]1=\$_sqz_result
  return 0
}
])


dnl FETCH_CHECK_COMPILER_HALT_ON_ERROR
dnl -------------------------------------------------
dnl Verifies if the compiler actually halts after the
dnl compilation phase without generating any object
dnl code file, when the source compiles with errors.

AC_DEFUN([FETCH_CHECK_COMPILER_HALT_ON_ERROR], [
  AC_MSG_CHECKING([if compiler halts on compilation errors])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      #error force compilation error
    ]])
  ],[
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([compiler does not halt on compilation errors.])
  ],[
    AC_MSG_RESULT([yes])
  ])
])


dnl FETCH_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE
dnl -------------------------------------------------
dnl Verifies if the compiler actually halts after the
dnl compilation phase without generating any object
dnl code file, when the source code tries to define a
dnl type for a constant array with negative dimension.

AC_DEFUN([FETCH_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE], [
  AC_REQUIRE([FETCH_CHECK_COMPILER_HALT_ON_ERROR])dnl
  AC_MSG_CHECKING([if compiler halts on negative sized arrays])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      typedef char bad_t[sizeof(char) == sizeof(int) ? -1 : -1 ];
    ]],[[
      bad_t dummy;
    ]])
  ],[
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([compiler does not halt on negative sized arrays.])
  ],[
    AC_MSG_RESULT([yes])
  ])
])


dnl FETCH_CHECK_COMPILER_STRUCT_MEMBER_SIZE
dnl -------------------------------------------------
dnl Verifies if the compiler is capable of handling the
dnl size of a struct member, struct which is a function
dnl result, as a compilation-time condition inside the
dnl type definition of a constant array.

AC_DEFUN([FETCH_CHECK_COMPILER_STRUCT_MEMBER_SIZE], [
  AC_REQUIRE([FETCH_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE])dnl
  AC_MSG_CHECKING([if compiler struct member size checking works])
  tst_compiler_check_one_works="unknown"
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      struct mystruct {
        int  mi;
        char mc;
        struct mystruct *next;
      };
      struct mystruct myfunc();
      typedef char good_t1[sizeof(myfunc().mi) == sizeof(int)  ? 1 : -1 ];
      typedef char good_t2[sizeof(myfunc().mc) == sizeof(char) ? 1 : -1 ];
    ]],[[
      good_t1 dummy1;
      good_t2 dummy2;
    ]])
  ],[
    tst_compiler_check_one_works="yes"
  ],[
    tst_compiler_check_one_works="no"
    sed 's/^/cc-src: /' conftest.$ac_ext >&6
    sed 's/^/cc-err: /' conftest.err >&6
  ])
  tst_compiler_check_two_works="unknown"
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      struct mystruct {
        int  mi;
        char mc;
        struct mystruct *next;
      };
      struct mystruct myfunc();
      typedef char bad_t1[sizeof(myfunc().mi) != sizeof(int)  ? 1 : -1 ];
      typedef char bad_t2[sizeof(myfunc().mc) != sizeof(char) ? 1 : -1 ];
    ]],[[
      bad_t1 dummy1;
      bad_t2 dummy2;
    ]])
  ],[
    tst_compiler_check_two_works="no"
  ],[
    tst_compiler_check_two_works="yes"
  ])
  if test "$tst_compiler_check_one_works" = "yes" &&
    test "$tst_compiler_check_two_works" = "yes"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([compiler fails struct member size checking.])
  fi
])


dnl FETCH_CHECK_COMPILER_SYMBOL_HIDING
dnl -------------------------------------------------
dnl Verify if compiler supports hiding library internal symbols, setting
dnl shell variable supports_symbol_hiding value as appropriate, as well as
dnl variables symbol_hiding_CFLAGS and symbol_hiding_EXTERN when supported.

AC_DEFUN([FETCH_CHECK_COMPILER_SYMBOL_HIDING], [
  AC_REQUIRE([FETCH_CHECK_COMPILER])dnl
  AC_BEFORE([$0],[FETCH_CONFIGURE_SYMBOL_HIDING])dnl
  AC_MSG_CHECKING([if compiler supports hiding library internal symbols])
  supports_symbol_hiding="no"
  symbol_hiding_CFLAGS=""
  symbol_hiding_EXTERN=""
  tmp_CFLAGS=""
  tmp_EXTERN=""
  case "$compiler_id" in
    CLANG|APPLECLANG)
      dnl All versions of clang support -fvisibility=
      tmp_EXTERN="__attribute__((__visibility__(\"default\")))"
      tmp_CFLAGS="-fvisibility=hidden"
      supports_symbol_hiding="yes"
      ;;
    GNU_C)
      dnl Only gcc 3.4 or later
      if test "$compiler_num" -ge "304"; then
        if $CC --help --verbose 2>/dev/null | grep fvisibility= >/dev/null ; then
          tmp_EXTERN="__attribute__((__visibility__(\"default\")))"
          tmp_CFLAGS="-fvisibility=hidden"
          supports_symbol_hiding="yes"
        fi
      fi
      ;;
    INTEL_UNIX_C)
      dnl Only icc 9.0 or later
      if test "$compiler_num" -ge "900"; then
        if $CC --help --verbose 2>&1 | grep fvisibility= > /dev/null ; then
          tmp_save_CFLAGS="$CFLAGS"
          CFLAGS="$CFLAGS -fvisibility=hidden"
          AC_LINK_IFELSE([
            AC_LANG_PROGRAM([[
              #include <stdio.h>
            ]],[[
              printf("icc fvisibility bug test");
            ]])
          ],[
            tmp_EXTERN="__attribute__((__visibility__(\"default\")))"
            tmp_CFLAGS="-fvisibility=hidden"
            supports_symbol_hiding="yes"
          ])
          CFLAGS="$tmp_save_CFLAGS"
        fi
      fi
      ;;
    SUNPRO_C)
      if $CC 2>&1 | grep flags >/dev/null && $CC -flags | grep xldscope= >/dev/null ; then
        tmp_EXTERN="__global"
        tmp_CFLAGS="-xldscope=hidden"
        supports_symbol_hiding="yes"
      fi
      ;;
  esac
  if test "$supports_symbol_hiding" = "yes"; then
    tmp_save_CFLAGS="$CFLAGS"
    CFLAGS="$tmp_save_CFLAGS $tmp_CFLAGS"
    squeeze CFLAGS
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        $tmp_EXTERN char *dummy(char *buff);
        char *dummy(char *buff)
        {
          if(buff)
            return ++buff;
          else
            return buff;
        }
      ]],[[
        char b[16];
        char *r = dummy(&b[0]);
        if(r)
          return (int)*r;
      ]])
    ],[
      supports_symbol_hiding="yes"
      if test -f conftest.err; then
        grep 'visibility' conftest.err >/dev/null
        if test "$?" -eq "0"; then
          supports_symbol_hiding="no"
        fi
      fi
    ],[
      supports_symbol_hiding="no"
      echo " " >&6
      sed 's/^/cc-src: /' conftest.$ac_ext >&6
      sed 's/^/cc-err: /' conftest.err >&6
      echo " " >&6
    ])
    CFLAGS="$tmp_save_CFLAGS"
  fi
  if test "$supports_symbol_hiding" = "yes"; then
    AC_MSG_RESULT([yes])
    symbol_hiding_CFLAGS="$tmp_CFLAGS"
    symbol_hiding_EXTERN="$tmp_EXTERN"
  else
    AC_MSG_RESULT([no])
  fi
])


dnl FETCH_CHECK_COMPILER_PROTOTYPE_MISMATCH
dnl -------------------------------------------------
dnl Verifies if the compiler actually halts after the
dnl compilation phase without generating any object
dnl code file, when the source code tries to redefine
dnl a prototype which does not match previous one.

AC_DEFUN([FETCH_CHECK_COMPILER_PROTOTYPE_MISMATCH], [
  AC_REQUIRE([FETCH_CHECK_COMPILER_HALT_ON_ERROR])dnl
  AC_MSG_CHECKING([if compiler halts on function prototype mismatch])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <stdlib.h>
      int rand(int n);
      int rand(int n)
      {
        if(n)
          return ++n;
        else
          return n;
      }
    ]],[[
      int i[2]={0,0};
      int j = rand(i[0]);
      if(j)
        return j;
    ]])
  ],[
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([compiler does not halt on function prototype mismatch.])
  ],[
    AC_MSG_RESULT([yes])
  ])
])


dnl FETCH_VAR_MATCH (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Verifies if shell variable VARNAME contains VALUE.
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. If at least
dnl one word of VALUE is present in VARNAME the match
dnl is considered positive, otherwise false.

AC_DEFUN([FETCH_VAR_MATCH], [
  ac_var_match_word="no"
  for word1 in $[$1]; do
    for word2 in [$2]; do
      if test "$word1" = "$word2"; then
        ac_var_match_word="yes"
      fi
    done
  done
])


dnl FETCH_VAR_MATCH_IFELSE (VARNAME, VALUE,
dnl                        [ACTION-IF-MATCH], [ACTION-IF-NOT-MATCH])
dnl -------------------------------------------------
dnl This performs a FETCH_VAR_MATCH check and executes
dnl first branch if the match is positive, otherwise
dnl the second branch is executed.

AC_DEFUN([FETCH_VAR_MATCH_IFELSE], [
  FETCH_VAR_MATCH([$1],[$2])
  if test "$ac_var_match_word" = "yes"; then
  ifelse($3,,:,[$3])
  ifelse($4,,,[else
    $4])
  fi
])


dnl FETCH_VAR_STRIP (VARNAME, VALUE)
dnl -------------------------------------------------
dnl Contents of variable VARNAME and VALUE are handled
dnl as whitespace separated lists of words. Each word
dnl from VALUE is removed from VARNAME when present.

AC_DEFUN([FETCH_VAR_STRIP], [
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
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
  [$1]="$ac_var_stripped"
  squeeze [$1]
])

dnl FETCH_ADD_COMPILER_WARNINGS (WARNING-LIST, NEW-WARNINGS)
dnl -------------------------------------------------------
dnl Contents of variable WARNING-LIST and NEW-WARNINGS are
dnl handled as whitespace separated lists of words.
dnl Add each compiler warning from NEW-WARNINGS that has not
dnl been disabled via CFLAGS to WARNING-LIST.

AC_DEFUN([FETCH_ADD_COMPILER_WARNINGS], [
  AC_REQUIRE([FETCH_SHFUNC_SQUEEZE])dnl
  ac_var_added_warnings=""
  for warning in [$2]; do
    FETCH_VAR_MATCH(CFLAGS, [-Wno-$warning -W$warning])
    if test "$ac_var_match_word" = "no"; then
      ac_var_added_warnings="$ac_var_added_warnings -W$warning"
    fi
  done
  dnl squeeze whitespace out of result
  [$1]="$[$1] $ac_var_added_warnings"
  squeeze [$1]
])
