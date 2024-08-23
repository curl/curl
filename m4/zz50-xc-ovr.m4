#---------------------------------------------------------------------------
#
# zz50-xc-ovr.m4
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>
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


dnl Override some language related macros
dnl -------------------------------------------------
dnl This is done to prevent Libtool 1.5.X from doing
dnl unnecessary C++, Fortran and Java tests when only
dnl using C language and reduce resulting configure
dnl script by nearly 300 Kb.

m4_ifdef([AC_LIBTOOL_LANG_CXX_CONFIG],
  [m4_undefine([AC_LIBTOOL_LANG_CXX_CONFIG])])
m4_define([AC_LIBTOOL_LANG_CXX_CONFIG],[:])

m4_ifdef([AC_LIBTOOL_LANG_F77_CONFIG],
  [m4_undefine([AC_LIBTOOL_LANG_F77_CONFIG])])
m4_define([AC_LIBTOOL_LANG_F77_CONFIG],[:])

m4_ifdef([AC_LIBTOOL_LANG_GCJ_CONFIG],
  [m4_undefine([AC_LIBTOOL_LANG_GCJ_CONFIG])])
m4_define([AC_LIBTOOL_LANG_GCJ_CONFIG],[:])


dnl XC_OVR_ZZ50
dnl -------------------------------------------------
dnl Placing a call to this macro in configure.ac will
dnl make macros in this file visible to other macros
dnl used for same configure script, overriding those
dnl provided elsewhere.

AC_DEFUN([XC_OVR_ZZ50],
  [AC_BEFORE([$0],[AC_PROG_LIBTOOL])])
