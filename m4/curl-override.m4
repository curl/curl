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
dnl a c89 compiler and does not suport K&R.

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

