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


dnl CARES_INCLUDES_STRING
dnl -------------------------------------------------
dnl Set up variable with list of headers that must be
dnl included when string.h is to be included.

AC_DEFUN([CARES_INCLUDES_STRING], [
cares_includes_string="\
/* includes start */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
/* includes end */"
  AC_CHECK_HEADERS(
    sys/types.h string.h,
    [], [], [$cares_includes_string])
])


dnl CARES_CHECK_FUNC_STRDUP
dnl -------------------------------------------------
dnl Verify if strdup is available, prototyped, and
dnl can be compiled. If all of these are true, and
dnl usage has not been previously disallowed with
dnl shell variable cares_disallow_strdup, then
dnl HAVE_STRDUP will be defined.

AC_DEFUN([CARES_CHECK_FUNC_STRDUP], [
  AC_REQUIRE([CARES_INCLUDES_STRING])dnl
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
      $cares_includes_string
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
        $cares_includes_string
      ]],[[
        if(0 != strdup(0))
          return 1;
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
    if test "x$cares_disallow_strdup" != "xyes"; then
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
    ac_cv_func_strdup="yes"
  else
    AC_MSG_RESULT([no])
    ac_cv_func_strdup="no"
  fi
])

