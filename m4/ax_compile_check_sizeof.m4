# ============================================================================
#  https://www.gnu.org/software/autoconf-archive/ax_compile_check_sizeof.html
# ============================================================================
#
# SYNOPSIS
#
#   AX_COMPILE_CHECK_SIZEOF(TYPE [, HEADERS [, EXTRA_SIZES...]])
#
# DESCRIPTION
#
#   This macro checks for the size of TYPE using compile checks, not run
#   checks. You can supply extra HEADERS to look into. the check will cycle
#   through 1 2 4 8 16 and any EXTRA_SIZES the user supplies. If a match is
#   found, it will #define SIZEOF_`TYPE' to that value. Otherwise it will
#   emit a configure time error indicating the size of the type could not be
#   determined.
#
#   The trick is that C will not allow duplicate case labels. While this is
#   valid C code:
#
#     switch (0) case 0: case 1:;
#
#   The following is not:
#
#     switch (0) case 0: case 0:;
#
#   Thus, the AC_TRY_COMPILE will fail if the currently tried size does not
#   match.
#
#   Here is an example skeleton configure.in script, demonstrating the
#   macro's usage:
#
#     AC_PROG_CC
#     AC_CHECK_HEADERS(stddef.h unistd.h)
#     AC_TYPE_SIZE_T
#     AC_CHECK_TYPE(ssize_t, int)
#
#     headers='#ifdef HAVE_STDDEF_H
#     #include <stddef.h>
#     #endif
#     #ifdef HAVE_UNISTD_H
#     #include <unistd.h>
#     #endif
#     '
#
#     AX_COMPILE_CHECK_SIZEOF(char)
#     AX_COMPILE_CHECK_SIZEOF(short)
#     AX_COMPILE_CHECK_SIZEOF(int)
#     AX_COMPILE_CHECK_SIZEOF(long)
#     AX_COMPILE_CHECK_SIZEOF(unsigned char *)
#     AX_COMPILE_CHECK_SIZEOF(void *)
#     AX_COMPILE_CHECK_SIZEOF(size_t, $headers)
#     AX_COMPILE_CHECK_SIZEOF(ssize_t, $headers)
#     AX_COMPILE_CHECK_SIZEOF(ptrdiff_t, $headers)
#     AX_COMPILE_CHECK_SIZEOF(off_t, $headers)
#
# LICENSE
#
#   Copyright (c) 2008 Kaveh Ghazi <ghazi@caip.rutgers.edu>
#   Copyright (c) 2017 Reini Urban <rurban@cpan.org>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.
#
#   SPDX-License-Identifier: GPL-3.0-or-later

#serial 7

AU_ALIAS([AC_COMPILE_CHECK_SIZEOF], [AX_COMPILE_CHECK_SIZEOF])
AC_DEFUN([AX_COMPILE_CHECK_SIZEOF],
[changequote(<<, >>)dnl
dnl The name to #define.
define(<<AC_TYPE_NAME>>, translit(sizeof_$1, [a-z *], [A-Z_P]))dnl
dnl The cache variable name.
define(<<AC_CV_NAME>>, translit(ac_cv_sizeof_$1, [ *], [_p]))dnl
changequote([, ])dnl
AC_MSG_CHECKING(size of $1)
AC_CACHE_VAL(AC_CV_NAME,
[for ac_size in 4 8 1 2 16 $3 ; do # List sizes in rough order of prevalence.
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
$2
]], [[switch (0) case 0: case (sizeof ($1) == $ac_size):;]])], [AC_CV_NAME=$ac_size])
  if test x$AC_CV_NAME != x ; then break; fi
done
])
if test x$AC_CV_NAME = x ; then
  AC_MSG_ERROR([cannot determine a size for $1])
fi
AC_MSG_RESULT($AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_TYPE_NAME, $AC_CV_NAME, [The number of bytes in type $1])
undefine([AC_TYPE_NAME])dnl
undefine([AC_CV_NAME])dnl
])
