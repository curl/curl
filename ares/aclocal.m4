dnl $Id$

dnl Copyright 1996 by the Massachusetts Institute of Technology.
dnl
dnl Permission to use, copy, modify, and distribute this
dnl software and its documentation for any purpose and without
dnl fee is hereby granted, provided that the above copyright
dnl notice appear in all copies and that both that copyright
dnl notice and this permission notice appear in supporting
dnl documentation, and that the name of M.I.T. not be used in
dnl advertising or publicity pertaining to distribution of the
dnl software without specific, written prior permission.
dnl M.I.T. makes no representations about the suitability of
dnl this software for any purpose.  It is provided "as is"
dnl without express or implied warranty.

dnl This file provides local macros for packages which use specific
dnl external libraries.  The public macros are:
dnl
dnl	ATHENA_UTIL_COM_ERR
dnl		Generates error if com_err not found.
dnl	ATHENA_UTIL_SS
dnl		Generates error if ss not found.
dnl	ATHENA_REGEXP
dnl		Sets REGEX_LIBS if rx library used; ensures POSIX
dnl		regexp support.
dnl	ATHENA_MOTIF
dnl		Sets MOTIF_LIBS and defines HAVE_MOTIF if Motif used.
dnl	ATHENA_MOTIF_REQUIRED
dnl		Generates error if Motif not found.
dnl	ATHENA_AFS
dnl		Sets AFS_LIBS and defines HAVE_AFS if AFS used.  Pass
dnl		in an argument giving the desired AFS libraries;
dnl		AFS_LIBS will be set to that value if AFS is found.
dnl		AFS_DIR will be set to the prefix given.
dnl	ATHENA_AFS_REQUIRED
dnl		Generates error if AFS libraries not found.  AFS_DIR
dnl		will be set to the prefix given.
dnl	ATHENA_KRB4
dnl		Sets KRB4_LIBS and defines HAVE_KRB4 if krb4 used.
dnl	ATHENA_KRB4_REQUIRED
dnl		Generates error if krb4 not found.  Sets KRB4_LIBS
dnl		otherwise.  (Special behavior because krb4 libraries
dnl		may be different if using krb4 compatibility libraries
dnl		from krb5.)
dnl	ATHENA_KRB5
dnl		Sets KRB5_LIBS and defines HAVE_KRB5 if krb5 used.
dnl	ATHENA_KRB5_REQUIRED
dnl		Generates error if krb5 not found.
dnl	ATHENA_HESIOD
dnl		Sets HESIOD_LIBS and defines HAVE_HESIOD if Hesiod
dnl		used.
dnl	ATHENA_HESIOD_REQUIRED
dnl		Generates error if Hesiod not found.
dnl	ATHENA_ARES
dnl		Sets ARES_LIBS and defines HAVE_ARES if libares
dnl		used.
dnl	ATHENA_ARES_REQUIRED
dnl		Generates error if libares not found.
dnl	ATHENA_ZEPHYR
dnl		Sets ZEPHYR_LIBS and defines HAVE_ZEPHYR if zephyr
dnl		used.
dnl	ATHENA_ZEPHYR_REQUIRED
dnl		Generates error if zephyr not found.
dnl
dnl All of the macros may extend CPPFLAGS and LDFLAGS to let the
dnl compiler find the requested libraries.  Put ATHENA_UTIL_COM_ERR
dnl and ATHENA_UTIL_SS before ATHENA_AFS or ATHENA_AFS_REQUIRED; there
dnl is a com_err library in the AFS libraries which requires -lutil.

dnl ----- com_err -----

AC_DEFUN(ATHENA_UTIL_COM_ERR,
[AC_ARG_WITH(com_err,
	[  --with-com_err=PREFIX   Specify location of com_err],
	[com_err="$withval"], [com_err=yes])
if test "$com_err" != no; then
	if test "$com_err" != yes; then
		CPPFLAGS="$CPPFLAGS -I$com_err/include"
		LDFLAGS="$LDFLAGS -L$com_err/lib"
	fi
	AC_CHECK_LIB(com_err, com_err, :,
		     [AC_MSG_ERROR(com_err library not found)])
else
	AC_MSG_ERROR(This package requires com_err.)
fi])

dnl ----- ss -----

AC_DEFUN(ATHENA_UTIL_SS,
[AC_ARG_WITH(ss,
	[  --with-ss=PREFIX        Specify location of ss (requires com_err)],
	[ss="$withval"], [ss=yes])
if test "$ss" != no; then
	if test "$ss" != yes; then
		CPPFLAGS="$CPPFLAGS -I$ss/include"
		LDFLAGS="$LDFLAGS -L$ss/lib"
	fi
	AC_CHECK_LIB(ss, ss_perror, :,
		     [AC_MSG_ERROR(ss library not found)], -lcom_err)
else
	AC_MSG_ERROR(This package requires ss.)
fi])

dnl ----- Regular expressions -----

AC_DEFUN(ATHENA_REGEXP,
[AC_ARG_WITH(regex,
	[  --with-regex=PREFIX     Use installed regex library],
	[regex="$withval"], [regex=no])
if test "$regex" != no; then
	if test "$regex" != yes; then
		CPPFLAGS="$CPPFLAGS -I$regex/include"
		LDFLAGS="$LDFLAGS -L$regex/lib"
	fi
	AC_CHECK_LIB(regex, regcomp, REGEX_LIBS=-lregex,
		     [AC_MSG_ERROR(regex library not found)])
else
	AC_CHECK_FUNC(regcomp, :,
		      [AC_MSG_ERROR(can't find POSIX regexp support)])
fi
AC_SUBST(REGEX_LIBS)])

dnl ----- Motif -----

AC_DEFUN(ATHENA_MOTIF_CHECK,
[if test "$motif" != yes; then
	CPPFLAGS="$CPPFLAGS -I$motif/include"
	LDFLAGS="$LDFLAGS -L$motif/lib"
fi
AC_CHECK_LIB(Xm, XmStringFree, :, [AC_MSG_ERROR(Motif library not found)])])

AC_DEFUN(ATHENA_MOTIF,
[AC_ARG_WITH(motif,
	[  --with-motif=PREFIX     Use Motif],
	[motif="$withval"], [motif=no])
if test "$motif" != no; then
	ATHENA_MOTIF_CHECK
	MOTIF_LIBS=-lXm
	AC_DEFINE(HAVE_MOTIF)
fi
AC_SUBST(MOTIF_LIBS)])

AC_DEFUN(ATHENA_MOTIF_REQUIRED,
[AC_ARG_WITH(motif,
	[  --with-motif=PREFIX     Specify location of Motif],
	[motif="$withval"], [motif=yes])
if test "$motif" != no; then
	ATHENA_MOTIF_CHECK
else
	AC_MSG_ERROR(This package requires Motif.)
fi])

dnl ----- AFS -----

AC_DEFUN(ATHENA_AFS_CHECK,
[AC_CHECK_FUNC(insque, :, AC_CHECK_LIB(compat, insque))
AC_CHECK_FUNC(gethostbyname, :, AC_CHECK_LIB(nsl, gethostbyname))
AC_CHECK_FUNC(socket, :, AC_CHECK_LIB(socket, socket))
if test "$afs" != yes; then
	CPPFLAGS="$CPPFLAGS -I$afs/include"
	LDFLAGS="$LDFLAGS -L$afs/lib -L$afs/lib/afs"
fi
AC_CHECK_LIB(sys, pioctl, :, [AC_MSG_ERROR(AFS libraries not found)],
	     -lrx -llwp -lsys)
AFS_DIR=$afs
AC_SUBST(AFS_DIR)])

dnl Specify desired AFS libraries as a parameter.
AC_DEFUN(ATHENA_AFS,
[AC_ARG_WITH(afs,
	[  --with-afs=PREFIX       Use AFS libraries],
	[afs="$withval"], [afs=no])
if test "$afs" != no; then
	ATHENA_AFS_CHECK
	AFS_LIBS=$1
	AC_DEFINE(HAVE_AFS)
fi
AC_SUBST(AFS_LIBS)])

AC_DEFUN(ATHENA_AFS_REQUIRED,
[AC_ARG_WITH(afs,
	[  --with-afs=PREFIX       Specify location of AFS libraries],
	[afs="$withval"], [afs=/usr/afsws])
if test "$afs" != no; then
	ATHENA_AFS_CHECK
else
	AC_MSG_ERROR(This package requires AFS libraries.)
fi])

dnl ----- Kerberos 4 -----

AC_DEFUN(ATHENA_KRB4_CHECK,
[AC_CHECK_FUNC(gethostbyname, :, AC_CHECK_LIB(nsl, gethostbyname))
AC_CHECK_FUNC(socket, :, AC_CHECK_LIB(socket, socket))
AC_CHECK_LIB(gen, compile)
if test "$krb4" != yes; then
	CPPFLAGS="$CPPFLAGS -I$krb4/include"
	if test -d "$krb4/include/kerberosIV"; then
		CPPFLAGS="$CPPFLAGS -I$krb4/include/kerberosIV"
	fi
	LDFLAGS="$LDFLAGS -L$krb4/lib"
fi
AC_CHECK_LIB(krb4, krb_rd_req,
	     [KRB4_LIBS="-lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err"],
	     [AC_CHECK_LIB(krb, krb_rd_req,
			   [KRB4_LIBS="-lkrb -ldes"],
			   [AC_MSG_ERROR(Kerberos 4 libraries not found)],
			   -ldes)],
	     -ldes425 -lkrb5 -lk5crypto -lcom_err)])

AC_DEFUN(ATHENA_KRB4,
[AC_ARG_WITH(krb4,
	[  --with-krb4=PREFIX      Use Kerberos 4],
	[krb4="$withval"], [krb4=no])
if test "$krb4" != no; then
	ATHENA_KRB4_CHECK
	AC_DEFINE(HAVE_KRB4)
fi
AC_SUBST(KRB4_LIBS)])

AC_DEFUN(ATHENA_KRB4_REQUIRED,
[AC_ARG_WITH(krb4,
	[  --with-krb4=PREFIX      Specify location of Kerberos 4],
	[krb4="$withval"], [krb4=yes])
if test "$krb4" != no; then
	ATHENA_KRB4_CHECK
	AC_SUBST(KRB4_LIBS)
else
	AC_MSG_ERROR(This package requires Kerberos 4.)
fi])

dnl ----- Kerberos 5 -----

AC_DEFUN(ATHENA_KRB5_CHECK,
[AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket)
AC_CHECK_LIB(gen, compile)
if test "$krb5" != yes; then
	CPPFLAGS="$CPPFLAGS -I$krb5/include"
	LDFLAGS="$LDFLAGS -L$krb5/lib"
fi
AC_CHECK_LIB(krb5, krb5_init_context, :,
	     [AC_MSG_ERROR(Kerberos 5 libraries not found)],
	     -lk5crypto -lcom_err)])

AC_DEFUN(ATHENA_KRB5,
[AC_ARG_WITH(krb5,
	[  --with-krb5=PREFIX      Use Kerberos 5],
	[krb5="$withval"], [krb5=no])
if test "$krb5" != no; then
	ATHENA_KRB5_CHECK
	KRB5_LIBS="-lkrb5 -lk5crypto -lcom_err"
	AC_DEFINE(HAVE_KRB5)
fi
AC_SUBST(KRB5_LIBS)])

AC_DEFUN(ATHENA_KRB5_REQUIRED,
[AC_ARG_WITH(krb5,
	[  --with-krb5=PREFIX      Specify location of Kerberos 5],
	[krb5="$withval"], [krb5=yes])
if test "$krb5" != no; then
	ATHENA_KRB5_CHECK
else
	AC_MSG_ERROR(This package requires Kerberos 5.)
fi])

dnl ----- Hesiod -----

AC_DEFUN(ATHENA_HESIOD_CHECK,
[AC_CHECK_FUNC(res_send, :, AC_CHECK_LIB(resolv, res_send))
if test "$hesiod" != yes; then
	CPPFLAGS="$CPPFLAGS -I$hesiod/include"
	LDFLAGS="$LDFLAGS -L$hesiod/lib"
fi
AC_CHECK_LIB(hesiod, hes_resolve, :,
	     [AC_MSG_ERROR(Hesiod library not found)])])

AC_DEFUN(ATHENA_HESIOD,
[AC_ARG_WITH(hesiod,
	[  --with-hesiod=PREFIX    Use Hesiod],
	[hesiod="$withval"], [hesiod=no])
if test "$hesiod" != no; then
	ATHENA_HESIOD_CHECK
	HESIOD_LIBS="-lhesiod"
	AC_DEFINE(HAVE_HESIOD)
fi
AC_SUBST(HESIOD_LIBS)])

AC_DEFUN(ATHENA_HESIOD_REQUIRED,
[AC_ARG_WITH(hesiod,
	[  --with-hesiod=PREFIX    Specify location of Hesiod],
	[hesiod="$withval"], [hesiod=yes])
if test "$hesiod" != no; then
	ATHENA_HESIOD_CHECK
else
	AC_MSG_ERROR(This package requires Hesiod.)
fi])

dnl ----- libares -----

AC_DEFUN(ATHENA_ARES_CHECK,
[AC_CHECK_FUNC(res_send, :, AC_CHECK_LIB(resolv, res_send))
if test "$ares" != yes; then
	CPPFLAGS="$CPPFLAGS -I$ares/include"
	LDFLAGS="$LDFLAGS -L$ares/lib"
fi
AC_CHECK_LIB(ares, ares_init, :, [AC_MSG_ERROR(libares not found)])])

AC_DEFUN(ATHENA_ARES,
[AC_ARG_WITH(ares,
	[  --with-ares=PREFIX      Use libares],
	[ares="$withval"], [ares=no])
if test "$ares" != no; then
	ATHENA_ARES_CHECK
	ARES_LIBS="-lares"
	AC_DEFINE(HAVE_ARES)
fi
AC_SUBST(ARES_LIBS)])

AC_DEFUN(ATHENA_ARES_REQUIRED,
[AC_ARG_WITH(ares,
	[  --with-ares=PREFIX      Specify location of libares],
	[ares="$withval"], [ares=yes])
if test "$ares" != no; then
	ATHENA_ARES_CHECK
else
	AC_MSG_ERROR(This package requires libares.)
fi])
dnl ----- zephyr -----

AC_DEFUN(ATHENA_ZEPHYR_CHECK,
[if test "$zephyr" != yes; then
	CPPFLAGS="$CPPFLAGS -I$zephyr/include"
	LDFLAGS="$LDFLAGS -L$zephyr/lib"
fi
AC_CHECK_LIB(zephyr, ZFreeNotice, :, [AC_MSG_ERROR(zephyr not found)])])

AC_DEFUN(ATHENA_ZEPHYR,
[AC_ARG_WITH(zephyr,
	[  --with-zephyr=PREFIX      Use zephyr],
	[zephyr="$withval"], [zephyr=no])
if test "$zephyr" != no; then
	ATHENA_ZEPHYR_CHECK
	ZEPHYR_LIBS="-lzephyr"
	AC_DEFINE(HAVE_ZEPHYR)
fi
AC_SUBST(ZEPHYR_LIBS)])

AC_DEFUN(ATHENA_ZEPHYR_REQUIRED,
[AC_ARG_WITH(zephyr,
	[  --with-zephyr=PREFIX      Specify location of zephyr],
	[zephyr="$withval"], [zephyr=yes])
if test "$zephyr" != no; then
	ATHENA_ZEPHYR_CHECK
else
	AC_MSG_ERROR(This package requires zephyr.)
fi])
