#---------------------------------------------------------------------------
#
# zz60-xc-ovr.m4
#
# Copyright (c) 2013 - 2022, Daniel Stenberg <daniel@haxx.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# SPDX-License-Identifier: ISC
#
#---------------------------------------------------------------------------

# serial 1


dnl The funny name of this file is intentional in order to make it
dnl sort alphabetically after any libtool, autoconf or automake
dnl provided .m4 macro file that might get copied into this same
dnl subdirectory. This allows that macro (re)definitions from this
dnl file may override those provided in other files.


dnl Override an autoconf provided macro
dnl -------------------------------------------------
dnl This macro overrides the one provided by autoconf
dnl 2.58 or newer, and provides macro definition for
dnl autoconf 2.57 or older which lack it. This allows
dnl using libtool 2.2 or newer, which requires that
dnl this macro is used in configure.ac, with autoconf
dnl 2.57 or older.

m4_ifdef([AC_CONFIG_MACRO_DIR],
[dnl
m4_undefine([AC_CONFIG_MACRO_DIR])dnl
])
m4_define([AC_CONFIG_MACRO_DIR],[])


dnl XC_OVR_ZZ60
dnl -------------------------------------------------
dnl Placing a call to this macro in configure.ac will
dnl make macros in this file visible to other macros
dnl used for same configure script, overriding those
dnl provided elsewhere.

AC_DEFUN([XC_OVR_ZZ60],
[dnl
AC_BEFORE([$0],[LT_INIT])dnl
AC_BEFORE([$0],[AM_INIT_AUTOMAKE])dnl
AC_BEFORE([$0],[AC_LIBTOOL_WIN32_DLL])dnl
AC_BEFORE([$0],[AC_PROG_LIBTOOL])dnl
dnl
AC_BEFORE([$0],[AC_CONFIG_MACRO_DIR])dnl
AC_BEFORE([$0],[AC_CONFIG_MACRO_DIRS])dnl
])
