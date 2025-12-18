#---------------------------------------------------------------------------
#
# xc-am-iface.m4
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


dnl _XC_AUTOMAKE_BODY
dnl -------------------------------------------------
dnl Private macro.
dnl
dnl This macro performs embedding of automake initialization
dnl code into configure script. When automake version 1.14 or
dnl newer is used at configure script generation time, this
dnl results in 'subdir-objects' automake option being used.
dnl When using automake versions older than 1.14 this option
dnl is not used when generating configure script.
dnl
dnl Existence of automake _AM_PROG_CC_C_O m4 private macro
dnl is used to differentiate automake version 1.14 from older
dnl ones which lack this macro.

m4_define([_XC_AUTOMAKE_BODY],
[dnl
## --------------------------------------- ##
##  Start of automake initialization code  ##
## --------------------------------------- ##
m4_ifdef([_AM_PROG_CC_C_O],
[
AM_INIT_AUTOMAKE([subdir-objects])
],[
AM_INIT_AUTOMAKE
])dnl
## ------------------------------------- ##
##  End of automake initialization code  ##
## ------------------------------------- ##
dnl
m4_define([$0], [])[]dnl
])


dnl XC_AUTOMAKE
dnl -------------------------------------------------
dnl Public macro.
dnl
dnl This macro embeds automake machinery into configure
dnl script regardless of automake version used in order
dnl to generate configure script.
dnl
dnl When using automake version 1.14 or newer, automake
dnl initialization option 'subdir-objects' is used to
dnl generate the configure script, otherwise this option
dnl is not used.

AC_DEFUN([XC_AUTOMAKE],
[dnl
AC_PREREQ([2.50])dnl
dnl
AC_BEFORE([$0],[AM_INIT_AUTOMAKE])dnl
dnl
_XC_AUTOMAKE_BODY
dnl
m4_ifdef([AM_INIT_AUTOMAKE],
  [m4_undefine([AM_INIT_AUTOMAKE])])dnl
dnl
m4_define([$0], [])[]dnl
])
