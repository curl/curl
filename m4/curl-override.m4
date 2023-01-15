#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
# SPDX-License-Identifier: curl
#
###########################################################################
#***************************************************************************
#***************************************************************************

# File version for 'aclocal' use. Keep it a single number.
# serial 7

dnl CURL_OVERRIDE_AUTOCONF
dnl -------------------------------------------------
dnl Placing a call to this macro in configure.ac after
dnl the one to AC_INIT will make macros in this file
dnl visible to the rest of the compilation overriding
dnl those from Autoconf.

AC_DEFUN([CURL_OVERRIDE_AUTOCONF], [
AC_BEFORE([$0],[AC_PROG_LIBTOOL])
# using curl-override.m4
])

dnl Override Autoconf's AC_LANG_PROGRAM (C)
dnl -------------------------------------------------
dnl This is done to prevent compiler warning
dnl 'function declaration isn't a prototype'
dnl in function main. This requires at least
dnl a c89 compiler and does not support K&R.

m4_define([AC_LANG_PROGRAM(C)],
[$1
int main (void)
{
$2
 ;
 return 0;
}])

dnl Override Autoconf's AC_LANG_CALL (C)
dnl -------------------------------------------------
dnl This is a backport of Autoconf's 2.60 with the
dnl embedded comments that hit the resulting script
dnl removed. This is done to reduce configure size
dnl and use fixed macro across Autoconf versions.

m4_define([AC_LANG_CALL(C)],
[AC_LANG_PROGRAM([$1
m4_if([$2], [main], ,
[
#ifdef __cplusplus
extern "C"
#endif
char $2 ();])], [return $2 ();])])

dnl Override Autoconf's AC_LANG_FUNC_LINK_TRY (C)
dnl -------------------------------------------------
dnl This is a backport of Autoconf's 2.60 with the
dnl embedded comments that hit the resulting script
dnl removed. This is done to reduce configure size
dnl and use fixed macro across Autoconf versions.

m4_define([AC_LANG_FUNC_LINK_TRY(C)],
[AC_LANG_PROGRAM(
[
#define $1 innocuous_$1
#ifdef __STDC__
# include <limits.h>
#else
# include <assert.h>
#endif
#undef $1
#ifdef __cplusplus
extern "C"
#endif
char $1 ();
#if defined __stub_$1 || defined __stub___$1
choke me
#endif
], [return $1 ();])])
