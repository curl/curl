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
# serial 1


dnl CARES_CHECK_OPTION_DEBUG
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-debug or --disable-debug, and set shell
dnl variable want_debug value as appropriate.

AC_DEFUN([CARES_CHECK_OPTION_DEBUG], [
  AC_BEFORE([$0],[CARES_CHECK_OPTION_WARNINGS])dnl
  AC_BEFORE([$0],[AC_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable debug build options])
  OPT_DEBUG_BUILD="default"
  AC_ARG_ENABLE(debug,
    AC_HELP_STRING([--enable-debug],[Enable debug build options])
    AC_HELP_STRING([--disable-debug],[Disable debug build options]),
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
      ;;
  esac
  AC_MSG_RESULT([$want_debug])
])


dnl CARES_CHECK_OPTION_WARNINGS
dnl -------------------------------------------------
dnl Verify if configure has been invoked with option
dnl --enable-warnings or --disable-warnings, and set
DNL shell variable want_warnings as appropriate.

AC_DEFUN([CARES_CHECK_OPTION_WARNINGS], [
  AC_REQUIRE([CARES_CHECK_OPTION_DEBUG])dnl
  AC_BEFORE([$0],[AC_PROG_CC])dnl
  AC_MSG_CHECKING([whether to enable strict compiler warnings])
  OPT_COMPILER_WARNINGS="default"
  AC_ARG_ENABLE(warnings,
    AC_HELP_STRING([--enable-warnings],[Enable strict compiler warnings])
    AC_HELP_STRING([--disable-warnings],[Disable strict compiler warnings]),
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
