#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id$
###########################################################################
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)

dnl We don't know the version number "statically" so we use a dash here
AC_INIT(curl, [-], [a suitable curl mailing list => http://curl.haxx.se/mail/])

dnl configure script copyright
AC_COPYRIGHT([Copyright (c) 1998 - 2008 Daniel Stenberg, <daniel@haxx.se>
This configure script may be copied, distributed and modified under the
terms of the curl license; see COPYING for more details])

AC_CONFIG_SRCDIR([lib/urldata.h])
AM_CONFIG_HEADER(lib/config.h src/config.h)
AM_MAINTAINER_MODE

dnl SED is needed by some of the tools
AC_PATH_PROG( SED, sed, sed-was-not-found-by-configure,
              $PATH:/usr/bin:/usr/local/bin)
AC_SUBST(SED)

if test "x$SED" = "xsed-was-not-found-by-configure"; then
  AC_MSG_WARN([sed was not found, this may ruin your chances to build fine])
fi

dnl AR is used by libtool, and try the odd Solaris path too
dnl we use AC_CHECK_TOOL since this should make a library for the target
dnl platform
AC_CHECK_TOOL(AR, ar,
              ar-was-not-found-by-configure,
              $PATH:/usr/bin:/usr/local/bin:/usr/ccs/bin)
AC_SUBST(AR)
if test "x$AR" = "xar-was-not-found-by-configure"; then
  AC_MSG_WARN([ar was not found, this may ruin your chances to build fine])
fi
AC_SUBST(libext)

dnl figure out the libcurl version
VERSION=`$SED -ne 's/^#define LIBCURL_VERSION "\(.*\)"/\1/p' ${srcdir}/include/curl/curlver.h`
AM_INIT_AUTOMAKE(curl,$VERSION)
AC_MSG_CHECKING([curl version])
AC_MSG_RESULT($VERSION)

dnl
dnl we extract the numerical version for curl-config only
VERSIONNUM=`$SED -ne 's/^#define LIBCURL_VERSION_NUM 0x\(.*\)/\1/p' ${srcdir}/include/curl/curlver.h`
AC_SUBST(VERSIONNUM)

dnl Solaris pkgadd support definitions
PKGADD_PKG="HAXXcurl"
PKGADD_NAME="cURL - a client that groks URLs"
PKGADD_VENDOR="curl.haxx.se"
AC_SUBST(PKGADD_PKG)
AC_SUBST(PKGADD_NAME)
AC_SUBST(PKGADD_VENDOR)

dnl
dnl initialize all the info variables
    curl_ssl_msg="no      (--with-ssl / --with-gnutls)"
    curl_ssh_msg="no      (--with-libssh2)"
   curl_zlib_msg="no      (--with-zlib)"
   curl_krb4_msg="no      (--with-krb4*)"
    curl_gss_msg="no      (--with-gssapi)"
 curl_spnego_msg="no      (--with-spnego)"
   curl_ares_msg="no      (--enable-ares)"
   curl_ipv6_msg="no      (--enable-ipv6)"
    curl_idn_msg="no      (--with-libidn)"
 curl_manual_msg="no      (--enable-manual)"
curl_verbose_msg="enabled (--disable-verbose)"
   curl_sspi_msg="no      (--enable-sspi)"
   curl_ldap_msg="no      (--enable-ldap / --with-ldap-lib / --with-lber-lib)"
  curl_ldaps_msg="no      (--enable-ldaps)"

dnl
dnl Save anything in $LIBS for later
dnl
ALL_LIBS=$LIBS

dnl
dnl Detect the canonical host and target build environment
dnl

AC_CANONICAL_HOST
dnl Get system canonical name
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

dnl Check for AIX weirdos
AC_AIX

dnl Checks for programs.
AC_PROG_CC

dnl check for how to do large files
AC_SYS_LARGEFILE

dnl support building of Windows DLLs
AC_LIBTOOL_WIN32_DLL

dnl skip libtool C++ and Fortran compiler checks
m4_ifdef([AC_PROG_CXX], [m4_undefine([AC_PROG_CXX])])
m4_defun([AC_PROG_CXX],[])
m4_ifdef([AC_PROG_CXXCPP], [m4_undefine([AC_PROG_CXXCPP])])
m4_defun([AC_PROG_CXXCPP],[true])
m4_ifdef([AC_PROG_F77], [m4_undefine([AC_PROG_F77])])
m4_defun([AC_PROG_F77],[])

dnl skip libtool C++ and Fortran linker checks
m4_ifdef([AC_LIBTOOL_CXX], [m4_undefine([AC_LIBTOOL_CXX])])
m4_defun([AC_LIBTOOL_CXX],[])
m4_ifdef([AC_LIBTOOL_CXXCPP], [m4_undefine([AC_LIBTOOL_CXXCPP])])
m4_defun([AC_LIBTOOL_CXXCPP],[true])
m4_ifdef([AC_LIBTOOL_F77], [m4_undefine([AC_LIBTOOL_F77])])
m4_defun([AC_LIBTOOL_F77],[])

dnl force libtool to build static libraries with PIC on AMD64-linux
AC_MSG_CHECKING([if arch-OS host is AMD64-linux (to build static libraries with PIC)])
case $host in
  x86_64*linux*)
    AC_MSG_RESULT([yes])
    with_pic=yes
    ;;
  *)
    AC_MSG_RESULT([no])
    ;;
esac

dnl libtool setup
AC_PROG_LIBTOOL

AC_MSG_CHECKING([if we need -no-undefined])
case $host in
  *-*-cygwin | *-*-mingw* | *-*-pw32*)
    need_no_undefined=yes
    ;;
  *)
    need_no_undefined=no
    ;;
esac
AC_MSG_RESULT($need_no_undefined)
AM_CONDITIONAL(NO_UNDEFINED, test x$need_no_undefined = xyes)

AC_MSG_CHECKING([if we need -mimpure-text])
mimpure=no
case $host in
  *-*-solaris2*)
    if test "$GCC" = "yes"; then
      mimpure="yes"
    fi
    ;;
  *)
    ;;
esac
AC_MSG_RESULT($mimpure)
AM_CONDITIONAL(MIMPURE, test x$mimpure = xyes)
AM_CONDITIONAL(STATICLIB, false)

AC_MSG_CHECKING([if we need BUILDING_LIBCURL])
case $host in
  *-*-mingw*)
    AC_DEFINE(BUILDING_LIBCURL, 1, [when building libcurl itself])
    AC_MSG_RESULT(yes)
    AC_MSG_CHECKING([if we need CURL_STATICLIB])
    if test "X$enable_shared" = "Xno"
    then
      AC_DEFINE(CURL_STATICLIB, 1, [when not building a shared library])
      AC_MSG_RESULT(yes)
      AM_CONDITIONAL(STATICLIB, true)
    else
      AC_MSG_RESULT(no)
    fi
    ;;
  *)
    AC_MSG_RESULT(no)
    ;;
esac

# Determine whether all dependent libraries must be specified when linking
if test "X$enable_shared" = "Xyes" -a "X$link_all_deplibs" = "Xno"
then
    REQUIRE_LIB_DEPS=no
else
    REQUIRE_LIB_DEPS=yes
fi
AC_SUBST(REQUIRE_LIB_DEPS)

dnl The install stuff has already been taken care of by the automake stuff
dnl AC_PROG_INSTALL
AC_PROG_MAKE_SET

dnl check if there's a way to force code inline
AC_C_INLINE

dnl **********************************************************************
dnl Make sure that our checks for headers windows.h winsock.h winsock2.h
dnl and ws2tcpip.h take precedence over any other further checks which
dnl could be done later using AC_CHECK_HEADER or AC_CHECK_HEADERS for
dnl this specific header files. And do them before its results are used.
dnl **********************************************************************

CURL_CHECK_HEADER_WINDOWS
CURL_CHECK_HEADER_WINSOCK
CURL_CHECK_HEADER_WINSOCK2
CURL_CHECK_HEADER_WS2TCPIP

CURL_CHECK_HEADER_WINLDAP
CURL_CHECK_HEADER_WINBER

dnl **********************************************************************
dnl platform/compiler/architecture specific checks/flags
dnl **********************************************************************

case $host in
  #
  x86_64*linux*)
    #
    dnl find out if icc is being used
    if test "z$ICC" = "z"; then
      CURL_DETECT_ICC
    fi
    #
    if test "$ICC" = "yes"; then
      dnl figure out icc version
      AC_MSG_CHECKING([icc version])
      iccver=`$CC -dumpversion`
      iccnhi=`echo $iccver | cut -d . -f1`
      iccnlo=`echo $iccver | cut -d . -f2`
      iccnum=`(expr $iccnhi "*" 100 + $iccnlo) 2>/dev/null`
      AC_MSG_RESULT($iccver)
      #
      if test "$iccnum" -ge "900" && test "$iccnum" -lt "1000"; then
        dnl icc 9.X specific
        CFLAGS="$CFLAGS -i-dynamic"
      fi
      #
      if test "$iccnum" -ge "1000"; then
        dnl icc 10.X or later
        CFLAGS="$CFLAGS -shared-intel"
      fi
      #
    fi
    ;;
  #
esac

dnl ************************************************************
dnl switch off particular protocols
dnl
AC_MSG_CHECKING([whether to support http])
AC_ARG_ENABLE(http,
AC_HELP_STRING([--enable-http],[Enable HTTP support])
AC_HELP_STRING([--disable-http],[Disable HTTP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_HTTP, 1, [to disable HTTP])
       AC_MSG_WARN([disable HTTP disables FTP over proxy])
       AC_SUBST(CURL_DISABLE_HTTP, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support ftp])
AC_ARG_ENABLE(ftp,
AC_HELP_STRING([--enable-ftp],[Enable FTP support])
AC_HELP_STRING([--disable-ftp],[Disable FTP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_FTP, 1, [to disable FTP])
       AC_SUBST(CURL_DISABLE_FTP, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support file])
AC_ARG_ENABLE(file,
AC_HELP_STRING([--enable-file],[Enable FILE support])
AC_HELP_STRING([--disable-file],[Disable FILE support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_FILE, 1, [to disable FILE])
       AC_SUBST(CURL_DISABLE_FILE, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support ldap])
AC_ARG_ENABLE(ldap,
AC_HELP_STRING([--enable-ldap],[Enable LDAP support])
AC_HELP_STRING([--disable-ldap],[Disable LDAP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
       AC_SUBST(CURL_DISABLE_LDAP, [1])
       ;;
  *)
       case $host in
         *-*-cygwin*)
           # Force no ldap. config/build process is broken for cygwin
           AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
           AC_SUBST(CURL_DISABLE_LDAP, [1])
           AC_MSG_RESULT(no)
           ;;
         *)
           AC_MSG_RESULT(yes)
       esac
       ;;
  esac ],[
       case $host in
         *-*-cygwin*)
           # Force no ldap. config/build process is broken for cygwin
           AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
           AC_SUBST(CURL_DISABLE_LDAP, [1])
           AC_MSG_RESULT(no)
           ;;
         *)
           AC_MSG_RESULT(yes)
       esac ]
)
AC_MSG_CHECKING([whether to support ldaps])
AC_ARG_ENABLE(ldaps,
AC_HELP_STRING([--enable-ldaps],[Enable LDAPS support])
AC_HELP_STRING([--disable-ldaps],[Disable LDAPS support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
       AC_SUBST(CURL_DISABLE_LDAPS, [1])
       ;;
  *)   if test x$CURL_DISABLE_LDAP = x1 ; then
               AC_MSG_RESULT(LDAP support needs to be enabled in order to enable LDAPS support!)
               AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
               AC_SUBST(CURL_DISABLE_LDAPS, [1])
       else
               AC_MSG_RESULT(yes)
               AC_DEFINE(HAVE_LDAP_SSL, 1, [Use LDAPS implementation])
               curl_ldaps_msg="enabled"
       fi
       ;;
  esac ],
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
       AC_SUBST(CURL_DISABLE_LDAPS, [1])
)

AC_MSG_CHECKING([whether to support dict])
AC_ARG_ENABLE(dict,
AC_HELP_STRING([--enable-dict],[Enable DICT support])
AC_HELP_STRING([--disable-dict],[Disable DICT support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_DICT, 1, [to disable DICT])
       AC_SUBST(CURL_DISABLE_DICT, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support telnet])
AC_ARG_ENABLE(telnet,
AC_HELP_STRING([--enable-telnet],[Enable TELNET support])
AC_HELP_STRING([--disable-telnet],[Disable TELNET support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_TELNET, 1, [to disable TELNET])
       AC_SUBST(CURL_DISABLE_TELNET, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support tftp])
AC_ARG_ENABLE(tftp,
AC_HELP_STRING([--enable-tftp],[Enable TFTP support])
AC_HELP_STRING([--disable-tftp],[Disable TFTP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_TFTP, 1, [to disable TFTP])
       AC_SUBST(CURL_DISABLE_TFTP, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl **********************************************************************
dnl Check for built-in manual
dnl **********************************************************************

AC_MSG_CHECKING([whether to provide built-in manual])
AC_ARG_ENABLE(manual,
AC_HELP_STRING([--enable-manual],[Enable built-in manual])
AC_HELP_STRING([--disable-manual],[Disable built-in manual]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)   AC_MSG_RESULT(yes)
       USE_MANUAL="1"
       ;;
  esac ],
       AC_MSG_RESULT(yes)
       USE_MANUAL="1"
)
dnl The actual use of the USE_MANUAL variable is done much later in this
dnl script to allow other actions to disable it as well.

dnl **********************************************************************
dnl check if this is the Intel ICC compiler, and if so make it stricter
dnl (convert warning 147 into an error) so that it properly can detect the
dnl gethostbyname_r() version
dnl **********************************************************************
CURL_DETECT_ICC([CFLAGS="$CFLAGS -we 147"])

dnl **********************************************************************
dnl Checks for libraries.
dnl **********************************************************************

dnl gethostbyname without lib or in the nsl lib?
AC_CHECK_FUNC(gethostbyname,
              [HAVE_GETHOSTBYNAME="1"
              ],
              [ AC_CHECK_LIB(nsl, gethostbyname,
                             [HAVE_GETHOSTBYNAME="1"
                             LIBS="$LIBS -lnsl"
                             ])
              ])

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the socket lib?
  AC_CHECK_LIB(socket, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="$LIBS -lsocket"
               ])
fi

dnl At least one system has been identified to require BOTH nsl and socket
dnl libs at the same time to link properly.
if test "$HAVE_GETHOSTBYNAME" != "1"
then
  AC_MSG_CHECKING([for gethostbyname with both nsl and socket libs])
  my_ac_save_LIBS=$LIBS
  LIBS="-lnsl -lsocket $LIBS"
  AC_TRY_LINK( ,
             [gethostbyname();],
             [ dnl found it!
             HAVE_GETHOSTBYNAME="1"
             AC_MSG_RESULT([yes])],
             [ dnl failed!
             AC_MSG_RESULT([no])
             dnl restore LIBS
             LIBS=$my_ac_save_LIBS]
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for Msys/Mingw
  AC_MSG_CHECKING([for gethostbyname in ws2_32])
  my_ac_save_LIBS=$LIBS
  LIBS="-lws2_32 $LIBS"
  AC_TRY_LINK([#include <winsock2.h>],
               [gethostbyname("www.dummysite.com");],
               [ dnl worked!
               ws2="yes"
               AC_MSG_RESULT([yes])
               HAVE_GETHOSTBYNAME="1"],
               [ dnl failed, restore LIBS
               LIBS=$my_ac_save_LIBS
               AC_MSG_RESULT(no)]
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for Minix 3.1
  AC_MSG_CHECKING([for gethostbyname for Minix 3])
  AC_TRY_LINK([
/* Older Minix versions may need <net/gen/netdb.h> here instead */
#include <netdb.h>],
               [gethostbyname("www.dummysite.com");],
               [ dnl worked!
               AC_MSG_RESULT([yes])
               HAVE_GETHOSTBYNAME="1"],
               AC_MSG_RESULT(no)
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for eCos with a stubbed DNS implementation
  AC_MSG_CHECKING([for gethostbyname for eCos])
  AC_TRY_LINK([
#include <stdio.h>
#include <netdb.h>],
               [gethostbyname("www.dummysite.com");],
               [ dnl worked!
               AC_MSG_RESULT([yes])
               HAVE_GETHOSTBYNAME="1"],
               AC_MSG_RESULT(no)
             )
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the net lib - for BeOS
  AC_CHECK_LIB(net, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="$LIBS -lnet"
               ])
fi


if test "$HAVE_GETHOSTBYNAME" = "1"; then
  AC_DEFINE(HAVE_GETHOSTBYNAME, 1, [If you have gethostbyname])
else
  AC_MSG_ERROR([couldn't find libraries for gethostbyname()])
fi

dnl resolve lib?
AC_CHECK_FUNC(strcasecmp, , [ AC_CHECK_LIB(resolve, strcasecmp) ])

if test "$ac_cv_lib_resolve_strcasecmp" = "$ac_cv_func_strcasecmp"; then
  AC_CHECK_LIB(resolve, strcasecmp,
              [LIBS="-lresolve $LIBS"],
               ,
               -lnsl)
fi

dnl socket lib?
AC_CHECK_FUNC(connect, , [ AC_CHECK_LIB(socket, connect) ])

dnl **********************************************************************
dnl The preceding library checks are all potentially useful for test
dnl servers (for providing networking support).  Save the list of required
dnl libraries at this point for use while linking those test servers.
dnl **********************************************************************
TEST_SERVER_LIBS=$LIBS

dnl **********************************************************************
AC_MSG_CHECKING([whether to use libgcc])
AC_ARG_ENABLE(libgcc,
AC_HELP_STRING([--enable-libgcc],[use libgcc when linking]),
[ case "$enableval" in
  yes)
        ALL_LIBS="$ALL_LIBS -lgcc"
       AC_MSG_RESULT(yes)
       ;;
  *)   AC_MSG_RESULT(no)
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl **********************************************************************
dnl Check for LDAP
dnl **********************************************************************

LDAPLIBNAME=""
AC_ARG_WITH(ldap-lib,
AC_HELP_STRING([--with-ldap-lib=libname],[Specify name of ldap lib file]),
 [LDAPLIBNAME="$withval"])

LBERLIBNAME=""
AC_ARG_WITH(lber-lib,
AC_HELP_STRING([--with-lber-lib=libname],[Specify name of lber lib file]),
 [LBERLIBNAME="$withval"])

if test x$CURL_DISABLE_LDAP != x1 ; then

  CURL_CHECK_HEADER_LBER
  CURL_CHECK_HEADER_LDAP
  CURL_CHECK_HEADER_LDAPSSL
  CURL_CHECK_HEADER_LDAP_SSL

  if test -z "$LDAPLIBNAME" ; then
    case $host in
      *-*-cygwin* | *-*-mingw* | *-*-pw32*)
        dnl Windows uses a single and unique OpenLDAP DLL name
        LDAPLIBNAME="wldap32"
        LBERLIBNAME="no"
        ;;
    esac
  fi

  if test "$LDAPLIBNAME" ; then
    AC_CHECK_LIB("$LDAPLIBNAME", ldap_init,, [
      AC_MSG_WARN(["$LDAPLIBNAME" is not an LDAP library: LDAP disabled])
      AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
      AC_SUBST(CURL_DISABLE_LDAP, [1])])
  else
    dnl Try to find the right ldap libraries for this system
    CURL_CHECK_LIBS_LDAP
    case X-"$curl_cv_ldap_LIBS" in
      X-unknown)
        AC_MSG_WARN([Cannot find libraries for LDAP support: LDAP disabled])
        AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
        AC_SUBST(CURL_DISABLE_LDAP, [1])
        ;;
    esac
  fi
fi

if test x$CURL_DISABLE_LDAP != x1 ; then

  if test "$LBERLIBNAME" ; then
    dnl If name is "no" then don't define this library at all
    dnl (it's only needed if libldap.so's dependencies are broken).
    if test "$LBERLIBNAME" != "no" ; then
      AC_CHECK_LIB("$LBERLIBNAME", ber_free,, [
        AC_MSG_WARN(["$LBERLIBNAME" is not an LBER library: LDAP disabled])
        AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
        AC_SUBST(CURL_DISABLE_LDAP, [1])])
    fi
  fi
fi

if test x$CURL_DISABLE_LDAP != x1 ; then
  AC_CHECK_FUNCS([ldap_url_parse])

  if test "$LDAPLIBNAME" = "wldap32"; then
    curl_ldap_msg="enabled (winldap)"
    AC_DEFINE(CURL_LDAP_WIN, 1, [Use W$ LDAP implementation])
    case $host in
      *-*-cygwin* | *-*-pw32*)
        AC_DEFINE(CURL_LDAP_HYBRID, 1, [W$ LDAP with non-W$ compiler])
        ;;
    esac
  else
    curl_ldap_msg="enabled (OpenLDAP)"
  fi
fi

dnl **********************************************************************
dnl Check for the presence of the winmm library.
dnl **********************************************************************

case $host in
  *-*-cygwin*)
    dnl Under Cygwin, winmm exists but is not needed as WIN32 is not #defined
    dnl and gettimeofday() will be used regardless of the outcome of this test.
    dnl Skip this test, otherwise -lwinmm will be needlessly added to LIBS
    dnl (and recorded as such in the .la file, potentially affecting downstream
    dnl clients of the library.)
    ;;
  *)
    AC_MSG_CHECKING([for timeGetTime in winmm])
    my_ac_save_LIBS=$LIBS
    LIBS="-lwinmm $LIBS"
    AC_TRY_LINK([#include <windef.h>
                 #include <mmsystem.h>
                 ],
                 [timeGetTime();],
                 [ dnl worked!
                 AC_MSG_RESULT([yes])
                 ],
                 [ dnl failed, restore LIBS
                 LIBS=$my_ac_save_LIBS
                 AC_MSG_RESULT(no)]
               )
    ;;
esac

dnl **********************************************************************
dnl Checks for IPv6
dnl **********************************************************************

AC_MSG_CHECKING([whether to enable ipv6])
AC_ARG_ENABLE(ipv6,
AC_HELP_STRING([--enable-ipv6],[Enable ipv6 (with ipv4) support])
AC_HELP_STRING([--disable-ipv6],[Disable ipv6 support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ipv6=no
       ;;
  *)   AC_MSG_RESULT(yes)
       ipv6=yes
       ;;
  esac ],

  AC_TRY_RUN([ /* is AF_INET6 available? */
#include <sys/types.h>
#include <sys/socket.h>
main()
{
 if (socket(AF_INET6, SOCK_STREAM, 0) < 0)
   exit(1);
 else
   exit(0);
}
],
  AC_MSG_RESULT(yes)
  ipv6=yes,
  AC_MSG_RESULT(no)
  ipv6=no,
  AC_MSG_RESULT(no)
  ipv6=no
))

if test "$ipv6" = "yes"; then
  curl_ipv6_msg="enabled"
fi

dnl **********************************************************************
dnl Check how non-blocking sockets are set
dnl **********************************************************************
AC_ARG_ENABLE(nonblocking,
AC_HELP_STRING([--enable-nonblocking],[Enable detecting how to do it])
AC_HELP_STRING([--disable-nonblocking],[Disable non-blocking socket detection]),
[
  if test "$enableval" = "no" ; then
    AC_MSG_WARN([non-blocking sockets disabled])
    AC_DEFINE(HAVE_DISABLED_NONBLOCKING, 1,
    [to disable NON-BLOCKING connections])
  else
    CURL_CHECK_NONBLOCKING_SOCKET
  fi
],
[
  CURL_CHECK_NONBLOCKING_SOCKET
])

dnl **********************************************************************
dnl Check if the operating system allows programs to write to their own argv[]
dnl **********************************************************************

AC_MSG_CHECKING([if argv can be written to])
AC_CACHE_VAL(curl_cv_writable_argv, [
AC_RUN_IFELSE([[
int main(int argc, char ** argv) {
        argv[0][0] = ' ';
        return (argv[0][0] == ' ')?0:1;
}
        ]],
        curl_cv_writable_argv=yes,
        curl_cv_writable_argv=no,
        curl_cv_writable_argv=cross)
])
case $curl_cv_writable_argv in
yes)
        AC_DEFINE(HAVE_WRITABLE_ARGV, 1, [Define this symbol if your OS supports changing the contents of argv])
        AC_MSG_RESULT(yes)
        ;;
no)
        AC_MSG_RESULT(no)
        ;;
*)
        AC_MSG_RESULT(no)
        AC_MSG_WARN([the previous check could not be made default was used])
        ;;
esac

dnl **********************************************************************
dnl Check for the presence of Kerberos4 libraries and headers
dnl **********************************************************************

AC_ARG_WITH(krb4-includes,
AC_HELP_STRING([--with-krb4-includes=DIR],
               [Specify location of kerberos4 headers]),[
 CPPFLAGS="$CPPFLAGS -I$withval"
 KRB4INC="$withval"
 want_krb4=yes
 ])

AC_ARG_WITH(krb4-libs,
AC_HELP_STRING([--with-krb4-libs=DIR],[Specify location of kerberos4 libs]),[
 LDFLAGS="$LDFLAGS -L$withval"
 KRB4LIB="$withval"
 want_krb4=yes
 ])


OPT_KRB4=off
AC_ARG_WITH(krb4,dnl
AC_HELP_STRING([--with-krb4=DIR],[where to look for Kerberos4]),[
  OPT_KRB4="$withval"
  if test X"$OPT_KRB4" != Xno; then
    want_krb4="yes"
    if test X"$OPT_KRB4" != Xyes; then
      LDFLAGS="$LDFLAGS -L$OPT_KRB4/lib$libsuff"
      KRB4LIB="$OPT_KRB4/lib$libsuff"
      CPPFLAGS="$CPPFLAGS -I$OPT_KRB4/include"
      KRB4INC="$OPT_KRB4/include"
    fi
  fi
 ])

AC_MSG_CHECKING([if Kerberos4 support is requested])

if test "$want_krb4" = yes
then
  if test "$ipv6" = "yes"; then
    echo krb4 is not compatible with IPv6
    exit 1
  fi
  AC_MSG_RESULT(yes)

  dnl Check for & handle argument to --with-krb4

  AC_MSG_CHECKING(where to look for Kerberos4)
  if test X"$OPT_KRB4" = Xyes
  then
    AC_MSG_RESULT([defaults])
  else
    AC_MSG_RESULT([libs in $KRB4LIB, headers in $KRB4INC])
  fi

  dnl Check for DES library
  AC_CHECK_LIB(des, des_pcbc_encrypt,
  [
    AC_CHECK_HEADERS(des.h)

    dnl resolv lib?
    AC_CHECK_FUNC(res_search, , [AC_CHECK_LIB(resolv, res_search)])

    dnl Check for the Kerberos4 library
    AC_CHECK_LIB(krb, krb_net_read,
    [
      dnl Check for header files
      AC_CHECK_HEADERS(krb.h)

      dnl we found the required libraries, add to LIBS
      LIBS="-lkrb -lcom_err -ldes $LIBS"

      dnl Check for function krb_get_our_ip_for_realm
      dnl this is needed for NAT networks
      AC_CHECK_FUNCS(krb_get_our_ip_for_realm)

      dnl add define KRB4
      AC_DEFINE(HAVE_KRB4, 1,
      [if you have the Kerberos4 libraries (including -ldes)])

      dnl substitute it too!
      KRB4_ENABLED=1
      AC_SUBST(KRB4_ENABLED)

      curl_krb4_msg="enabled"

      dnl the krb4 stuff needs a strlcpy()
      AC_CHECK_FUNCS(strlcpy)

    ])
  ])
else
  AC_MSG_RESULT(no)
fi

dnl **********************************************************************
dnl Check for FBopenssl(SPNEGO) libraries
dnl **********************************************************************

AC_ARG_WITH(spnego,
  AC_HELP_STRING([--with-spnego=DIR],
                 [Specify location of SPNEGO library fbopenssl]), [
  SPNEGO_ROOT="$withval"
  if test x"$SPNEGO_ROOT" != xno; then
    want_spnego="yes"
  fi
])

AC_MSG_CHECKING([if SPNEGO support is requested])
if test x"$want_spnego" = xyes; then

  if test X"$SPNEGO_ROOT" = Xyes; then
     AC_MSG_ERROR([FBOpenSSL libs and/or directories were not found where specified!])
     AC_MSG_RESULT(no)
  else
     if test -z "$SPNEGO_LIB_DIR"; then
        LDFLAGS="$LDFLAGS -L$SPNEGO_ROOT -lfbopenssl"
     else
        LDFLAGS="$LDFLAGS $SPNEGO_LIB_DIR"
     fi

     AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_SPNEGO, 1,
               [Define this if you have the SPNEGO library fbopenssl])
     curl_spnego_msg="enabled"
  fi
else
  AC_MSG_RESULT(no)
fi

dnl **********************************************************************
dnl Check for GSS-API libraries
dnl **********************************************************************

dnl check for gss stuff in the /usr as default

GSSAPI_ROOT="/usr"
AC_ARG_WITH(gssapi-includes,
  AC_HELP_STRING([--with-gssapi-includes=DIR],
                 [Specify location of GSSAPI header]),
  [ GSSAPI_INCS="-I$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi-libs,
  AC_HELP_STRING([--with-gssapi-libs=DIR],
                 [Specify location of GSSAPI libs]),
  [ GSSAPI_LIB_DIR="-L$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi,
  AC_HELP_STRING([--with-gssapi=DIR],
                 [Where to look for GSSAPI]), [
  GSSAPI_ROOT="$withval"
  if test x"$GSSAPI_ROOT" != xno; then
    want_gss="yes"
    if test x"$GSSAPI_ROOT" = xyes; then
      dnl if yes, then use default root
      GSSAPI_ROOT="/usr"
    fi
  fi
])

save_CPPFLAGS="$CPPFLAGS"
AC_MSG_CHECKING([if GSSAPI support is requested])
if test x"$want_gss" = xyes; then
  AC_MSG_RESULT(yes)

  if test -z "$GSSAPI_INCS"; then
     if test -f "$GSSAPI_ROOT/bin/krb5-config"; then
        GSSAPI_INCS=`$GSSAPI_ROOT/bin/krb5-config --cflags gssapi`
        GSSAPI_LIBS=`$GSSAPI_ROOT/bin/krb5-config --libs gssapi`
     elif test "$GSSAPI_ROOT" != "yes"; then
        GSSAPI_INCS="-I$GSSAPI_ROOT/include"
        GSSAPI_LIBS="-lgssapi"
     fi
  fi

  CPPFLAGS="$CPPFLAGS $GSSAPI_INCS"
  LIBS="$LIBS $GSSAPI_LIBS"

  AC_CHECK_HEADER(gss.h,
    [
      dnl found in the given dirs
      AC_DEFINE(HAVE_GSSGNU, 1, [if you have the GNU gssapi libraries])
      gnu_gss=yes
    ],
    [
      dnl not found, check Heimdal
      AC_CHECK_HEADER(gssapi.h,
        [
          dnl found in the given dirs
          AC_DEFINE(HAVE_GSSHEIMDAL, 1, [if you have the Heimdal gssapi libraries])
        ],
        [
          dnl not found, check in gssapi/ subdir
          AC_CHECK_HEADER(gssapi/gssapi.h,
            [
              dnl found
              AC_DEFINE(HAVE_GSSMIT, 1, [if you have the MIT gssapi libraries])
            ],
            [
              dnl no header found, disabling GSS
              want_gss=no
              AC_MSG_WARN(disabling GSSAPI since no header files was found)
            ]
          )
        ]
      )
    ]
  )
else
  AC_MSG_RESULT(no)
fi
if test x"$want_gss" = xyes; then
  AC_DEFINE(HAVE_GSSAPI, 1, [if you have the gssapi libraries])

  curl_gss_msg="enabled (MIT/Heimdal)"

  if test -n "$gnu_gss"; then
    curl_gss_msg="enabled (GNU GSS)"
    LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR -lgss"
  elif test -z "$GSSAPI_LIB_DIR"; then
     if test -f "$GSSAPI_ROOT/bin/krb5-config"; then
        gss_ldflags=`$GSSAPI_ROOT/bin/krb5-config --libs gssapi`
        LDFLAGS="$LDFLAGS $gss_ldflags"
     elif test "$GSSAPI_ROOT" != "yes"; then
        LDFLAGS="$LDFLAGS -L$GSSAPI_ROOT/lib$libsuff -lgssapi"
     else
        LDFLAGS="$LDFLAGS -lgssapi"
     fi
  else
     LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR -lgssapi"
  fi
else
  CPPFLAGS="$save_CPPFLAGS"
fi

dnl **********************************************************************
dnl Check for the presence of SSL libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for SSL files & libraries.
OPT_SSL=off
dnl Default to no CA bundle
ca="no"
AC_ARG_WITH(ssl,dnl
AC_HELP_STRING([--with-ssl=PATH],[Where to look for OpenSSL, PATH points to the SSL installation (default: /usr/local/ssl); when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AC_HELP_STRING([--without-ssl], [disable OpenSSL]),
  OPT_SSL=$withval)

if test X"$OPT_SSL" != Xno; then
  dnl backup the pre-ssl variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_SSL" in
  yes)
    dnl --with-ssl (without path) used
    if test x$cross_compiling != xyes; then
      dnl only do pkg-config magic when not cross-compiling
      PKGTEST="yes"
    fi
    PREFIX_OPENSSL=/usr/local/ssl
    LIB_OPENSSL="$PREFIX_OPENSSL/lib$libsuff"
    ;;
  off)
    dnl no --with-ssl option given, just check default places
    if test x$cross_compiling != xyes; then
      dnl only do pkg-config magic when not cross-compiling
      PKGTEST="yes"
    fi
    PREFIX_OPENSSL=
    ;;
  *)
    dnl check the given --with-ssl spot
    PKGTEST="no"
    PREFIX_OPENSSL=$OPT_SSL
    LIB_OPENSSL="$PREFIX_OPENSSL/lib$libsuff"
    LDFLAGS="$LDFLAGS -L$LIB_OPENSSL"
    CPPFLAGS="$CPPFLAGS -I$PREFIX_OPENSSL/include/openssl -I$PREFIX_OPENSSL/include"
    ;;
  esac

  if test "$PKGTEST" = "yes"; then

    dnl Detect the pkg-config tool, as it may have extra info about the
    dnl openssl installation we can use. I *believe* this is what we are
    dnl expected to do on really recent Redhat Linux hosts.

    AC_PATH_PROG( PKGCONFIG, pkg-config, no, $PATH:/usr/bin:/usr/local/bin)
    if test "$PKGCONFIG" != "no" ; then
      AC_MSG_CHECKING([OpenSSL options with pkg-config])

      $PKGCONFIG --exists openssl
      SSL_EXISTS=$?

      if test "$SSL_EXISTS" -eq "0"; then
        SSL_LIBS=`$PKGCONFIG --libs-only-l openssl 2>/dev/null`
        SSL_LDFLAGS=`$PKGCONFIG --libs-only-L openssl 2>/dev/null`
        SSL_CPPFLAGS=`$PKGCONFIG --cflags-only-I openssl 2>/dev/null`

        LIB_OPENSSL=`echo $SSL_LDFLAGS | sed -e 's/-L//g'`

        dnl use the values pkg-config reported
        LIBS="$LIBS $SSL_LIBS"
        CPPFLAGS="$CPPFLAGS $SSL_CPPFLAGS"
        LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
        AC_MSG_RESULT([found])
      else
        AC_MSG_RESULT([no])
      fi
    fi
  fi

  dnl This is for Msys/Mingw
  case $host in
    *-*-cygwin*)
      dnl Under Cygwin this is extraneous and causes an unnecessary -lgdi32
      dnl to be added to LIBS and recorded in the .la file.
      ;;
    *)
      AC_MSG_CHECKING([for gdi32])
      my_ac_save_LIBS=$LIBS
      LIBS="-lgdi32 $LIBS"
      AC_TRY_LINK([#include <windef.h>
                   #include <wingdi.h>],
                   [GdiFlush();],
                   [ dnl worked!
                   AC_MSG_RESULT([yes])],
                   [ dnl failed, restore LIBS
                   LIBS=$my_ac_save_LIBS
                   AC_MSG_RESULT(no)]
                  )
      ;;
  esac

  AC_CHECK_LIB(crypto, CRYPTO_lock,[
     HAVECRYPTO="yes"
     LIBS="-lcrypto $LIBS"
     ],[
     LDFLAGS="$CLEANLDFLAGS -L$LIB_OPENSSL"
     CPPFLAGS="$CLEANCPPFLAGS -I$PREFIX_OPENSSL/include/openssl -I$PREFIX_OPENSSL/include"
     AC_CHECK_LIB(crypto, CRYPTO_add_lock,[
       HAVECRYPTO="yes"
       LIBS="-lcrypto $LIBS"], [
       LDFLAGS="$CLEANLDFLAGS"
       CPPFLAGS="$CLEANCPPFLAGS"
       LIBS="$CLEANLIBS"
       ])
    ])


  if test X"$HAVECRYPTO" = X"yes"; then
    dnl This is only reasonable to do if crypto actually is there: check for
    dnl SSL libs NOTE: it is important to do this AFTER the crypto lib

    AC_CHECK_LIB(ssl, SSL_connect)

    if test "$ac_cv_lib_ssl_SSL_connect" != yes; then
        dnl we didn't find the SSL lib, try the RSAglue/rsaref stuff
        AC_MSG_CHECKING(for ssl with RSAglue/rsaref libs in use);
        OLIBS=$LIBS
        LIBS="$LIBS -lRSAglue -lrsaref"
        AC_CHECK_LIB(ssl, SSL_connect)
        if test "$ac_cv_lib_ssl_SSL_connect" != yes; then
            dnl still no SSL_connect
            AC_MSG_RESULT(no)
            LIBS=$OLIBS
        else
            AC_MSG_RESULT(yes)
        fi

    else

      dnl Have the libraries--check for SSLeay/OpenSSL headers
      AC_CHECK_HEADERS(openssl/x509.h openssl/rsa.h openssl/crypto.h \
                       openssl/pem.h openssl/ssl.h openssl/err.h,
        curl_ssl_msg="enabled (OpenSSL)"
        OPENSSL_ENABLED=1
        AC_DEFINE(USE_OPENSSL, 1, [if OpenSSL is in use]))

      if test $ac_cv_header_openssl_x509_h = no; then
        dnl we don't use the "action" part of the AC_CHECK_HEADERS macro
        dnl since 'err.h' might in fact find a krb4 header with the same
        dnl name
        AC_CHECK_HEADERS(x509.h rsa.h crypto.h pem.h ssl.h err.h)

        if test $ac_cv_header_x509_h = yes &&
           test $ac_cv_header_crypto_h = yes &&
           test $ac_cv_header_ssl_h = yes; then
          dnl three matches
          curl_ssl_msg="enabled (OpenSSL)"
          OPENSSL_ENABLED=1
        fi
      fi
    fi

    if test X"$OPENSSL_ENABLED" = X"1"; then
       AC_DEFINE(USE_SSLEAY, 1, [if SSL is enabled])

       dnl is there a pkcs12.h header present?
       AC_CHECK_HEADERS(openssl/pkcs12.h)
    else
       LIBS="$CLEANLIBS"
    fi
    dnl USE_SSLEAY is the historical name for what configure calls
    dnl OPENSSL_ENABLED; the names should really be unified
    USE_SSLEAY="$OPENSSL_ENABLED"
    AC_SUBST(USE_SSLEAY)

    if test X"$OPT_SSL" != Xoff &&
       test "$OPENSSL_ENABLED" != "1"; then
      AC_MSG_ERROR([OpenSSL libs and/or directories were not found where specified!])
    fi
  fi

  if test X"$OPENSSL_ENABLED" = X"1"; then
    dnl If the ENGINE library seems to be around, check for the OpenSSL engine
    dnl stuff, it is kind of "separated" from the main SSL check
    AC_CHECK_FUNC(ENGINE_init,
              [
                AC_CHECK_HEADERS(openssl/engine.h)
                AC_CHECK_FUNCS( ENGINE_load_builtin_engines )
              ])

    dnl these can only exist if openssl exists
    dnl yassl doesn't have SSL_get_shutdown

    AC_CHECK_FUNCS( RAND_status \
                    RAND_screen \
                    RAND_egd \
                    CRYPTO_cleanup_all_ex_data \
                    SSL_get_shutdown )

    dnl Make an attempt to detect if this is actually yassl's headers and
    dnl OpenSSL emulation layer. We still leave everything else believing
    dnl and acting like OpenSSL.

    AC_MSG_CHECKING([for yaSSL using OpenSSL compatibility mode])
    AC_TRY_COMPILE([
#include <openssl/ssl.h>
      ],[
#if defined(YASSL_VERSION) && defined(OPENSSL_VERSION_NUMBER)
        int dummy = SSL_ERROR_NONE;
#else
        Not the yaSSL OpenSSL compatibility header.
#endif
      ],[
        AC_MSG_RESULT([yes])
        AC_DEFINE_UNQUOTED(USE_YASSLEMUL, 1,
          [Define to 1 if using yaSSL in OpenSSL compatibility mode.])
        curl_ssl_msg="enabled (OpenSSL emulation by yaSSL)"
      ],[
        AC_MSG_RESULT([no])
    ])
  fi

  if test "$OPENSSL_ENABLED" = "1"; then
    if test -n "$LIB_OPENSSL"; then
       dnl when the ssl shared libs were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to LD_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$LIB_OPENSSL"
       export LD_LIBRARY_PATH
       AC_MSG_NOTICE([Added $LIB_OPENSSL to LD_LIBRARY_PATH])
    fi
  fi

fi

dnl **********************************************************************
dnl Check for the presence of ZLIB libraries and headers
dnl **********************************************************************

dnl Check for & handle argument to --with-zlib.

_cppflags=$CPPFLAGS
_ldflags=$LDFLAGS
AC_ARG_WITH(zlib,
AC_HELP_STRING([--with-zlib=PATH],[search for zlib in PATH])
AC_HELP_STRING([--without-zlib],[disable use of zlib]),
               [OPT_ZLIB="$withval"])

if test "$OPT_ZLIB" = "no" ; then
    AC_MSG_WARN([zlib disabled])
else
  if test "$OPT_ZLIB" = "yes" ; then
     OPT_ZLIB=""
  fi

  if test -z "$OPT_ZLIB" ; then
    dnl check for the lib first without setting any new path, since many
    dnl people have it in the default path

    AC_CHECK_LIB(z, inflateEnd,
                   dnl libz found, set the variable
                   [HAVE_LIBZ="1"],
                   dnl if no lib found, try /usr/local
                   [OPT_ZLIB="/usr/local"])

  fi

  dnl Add a nonempty path to the compiler flags
  if test -n "$OPT_ZLIB"; then
     CPPFLAGS="$CPPFLAGS -I$OPT_ZLIB/include"
     LDFLAGS="$LDFLAGS -L$OPT_ZLIB/lib$libsuff"
  fi

  AC_CHECK_HEADER(zlib.h,
    [
    dnl zlib.h was found
    HAVE_ZLIB_H="1"
    dnl if the lib wasn't found already, try again with the new paths
    if test "$HAVE_LIBZ" != "1"; then
      AC_CHECK_LIB(z, gzread,
                   [
                   dnl the lib was found!
                   HAVE_LIBZ="1"
                   ],
                   [ CPPFLAGS=$_cppflags
                   LDFLAGS=$_ldflags])
    fi
    ],
    [
      dnl zlib.h was not found, restore the flags
      CPPFLAGS=$_cppflags
      LDFLAGS=$_ldflags]
    )

  if test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" != "1"
  then
    AC_MSG_WARN([configure found only the libz lib, not the header file!])
    HAVE_LIBZ=""
  elif test "$HAVE_LIBZ" != "1" && test "$HAVE_ZLIB_H" = "1"
  then
    AC_MSG_WARN([configure found only the libz header file, not the lib!])
  elif test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" = "1"
  then
    dnl both header and lib were found!
    AC_SUBST(HAVE_LIBZ)
    AC_DEFINE(HAVE_ZLIB_H, 1, [if you have the zlib.h header file])
    AC_DEFINE(HAVE_LIBZ, 1, [if zlib is available])

    CURL_LIBS="$CURL_LIBS -lz"
    LIBS="$LIBS -lz"

    dnl replace 'HAVE_LIBZ' in the automake makefile.ams
    AMFIXLIB="1"
    AC_MSG_NOTICE([found both libz and libz.h header])
    curl_zlib_msg="enabled"
  fi
fi

dnl set variable for use in automakefile(s)
AM_CONDITIONAL(HAVE_LIBZ, test x"$AMFIXLIB" = x1)

dnl **********************************************************************
dnl Check for the presence of LIBSSH2 libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for LIBSSH2 files & libraries.
OPT_LIBSSH2=off
AC_ARG_WITH(libssh2,dnl
AC_HELP_STRING([--with-libssh2=PATH],[Where to look for libssh2, PATH points to the LIBSSH2 installation (default: /usr/local/lib); when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AC_HELP_STRING([--without-libssh2], [disable LIBSSH2]),
  OPT_LIBSSH2=$withval)

if test X"$OPT_LIBSSH2" != Xno; then
  dnl backup the pre-libssh2 variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_LIBSSH2" in
  yes)
    dnl --with-libssh2 (without path) used
    PREFIX_LIBSSH2=/usr/local/lib
    LIB_LIBSSH2="$PREFIX_LIBSSH2/lib$libsuff"
    ;;
  off)
    dnl no --with-libssh2 option given, just check default places
    PREFIX_LIBSSH2=
    ;;
  *)
    dnl use the given --with-libssh2 spot
    PREFIX_LIBSSH2=$OPT_LIBSSH2
    LIB_LIBSSH2="$PREFIX_LIBSSH2/lib$libsuff"
    LDFLAGS="$LDFLAGS -L$LIB_LIBSSH2"
    CPPFLAGS="$CPPFLAGS -I$PREFIX_LIBSSH2/include"
    ;;
  esac

  AC_CHECK_LIB(ssh2, libssh2_channel_open_ex)

  AC_CHECK_HEADERS(libssh2.h,
    curl_ssh_msg="enabled (libSSH2)"
    LIBSSH2_ENABLED=1
    AC_DEFINE(USE_LIBSSH2, 1, [if libSSH2 is in use])
    AC_SUBST(USE_LIBSSH2, [1])
  )

  if test X"$OPT_LIBSSH2" != Xoff &&
     test "$LIBSSH2_ENABLED" != "1"; then
    AC_MSG_ERROR([libSSH2 libs and/or directories were not found where specified!])
  fi

  if test "$LIBSSH2_ENABLED" = "1"; then
    if test -n "$LIB_LIBSSH2"; then
       dnl when the libssh2 shared libs were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to LD_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$LIB_LIBSSH2"
       export LD_LIBRARY_PATH
       AC_MSG_NOTICE([Added $LIB_LIBSSH2 to LD_LIBRARY_PATH])
    fi
  fi
fi

dnl **********************************************************************
dnl Check for the random seed preferences
dnl **********************************************************************

if test X"$OPENSSL_ENABLED" = X"1"; then
  AC_ARG_WITH(egd-socket,
  AC_HELP_STRING([--with-egd-socket=FILE],
                 [Entropy Gathering Daemon socket pathname]),
      [ EGD_SOCKET="$withval" ]
  )
  if test -n "$EGD_SOCKET" ; then
          AC_DEFINE_UNQUOTED(EGD_SOCKET, "$EGD_SOCKET",
          [your Entropy Gathering Daemon socket pathname] )
  fi

  dnl Check for user-specified random device
  AC_ARG_WITH(random,
  AC_HELP_STRING([--with-random=FILE],
                 [read randomness from FILE (default=/dev/urandom)]),
      [ RANDOM_FILE="$withval" ],
      [
          dnl Check for random device
          AC_CHECK_FILE("/dev/urandom", [ RANDOM_FILE="/dev/urandom"] )
      ]
  )
  if test -n "$RANDOM_FILE" && test X"$RANDOM_FILE" != Xno ; then
          AC_SUBST(RANDOM_FILE)
          AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE",
          [a suitable file to read random data from])
  fi
fi

dnl ----------------------------------------------------
dnl FIX: only check for GnuTLS if OpenSSL is not enabled
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for GnuTLS files & libraries.
OPT_GNUTLS=no

AC_ARG_WITH(gnutls,dnl
AC_HELP_STRING([--with-gnutls=PATH],[where to look for GnuTLS, PATH points to the installation root (default: /usr/local/)])
AC_HELP_STRING([--without-gnutls], [disable GnuTLS detection]),
  OPT_GNUTLS=$withval)

if test "$OPENSSL_ENABLED" != "1"; then

  if test X"$OPT_GNUTLS" != Xno; then
    if test "x$OPT_GNUTLS" = "xyes"; then
     check=`libgnutls-config --version 2>/dev/null`
     if test -n "$check"; then
       addlib=`libgnutls-config --libs`
       addcflags=`libgnutls-config --cflags`
       version=`libgnutls-config --version`
       gtlsprefix=`libgnutls-config --prefix`
     fi
    else
      addlib=`$OPT_GNUTLS/bin/libgnutls-config --libs`
      addcflags=`$OPT_GNUTLS/bin/libgnutls-config --cflags`
      version=`$OPT_GNUTLS/bin/libgnutls-config --version 2>/dev/null`
      gtlsprefix=$OPT_GNUTLS
      if test -z "$version"; then
        version="unknown"
      fi
    fi
    if test -n "$addlib"; then

      CLEANLIBS="$LIBS"
      CLEANCPPFLAGS="$CPPFLAGS"

      LIBS="$LIBS $addlib"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(gnutls, gnutls_check_version,
       [
       AC_DEFINE(USE_GNUTLS, 1, [if GnuTLS is enabled])
       AC_SUBST(USE_GNUTLS, [1])
       GNUTLS_ENABLED=1
       USE_GNUTLS="yes"
       curl_ssl_msg="enabled (GnuTLS)"
       ],
       [
         LIBS="$CLEANLIBS"
         CPPFLAGS="$CLEANCPPFLAGS"
       ])

      if test "x$USE_GNUTLS" = "xyes"; then
        AC_MSG_NOTICE([detected GnuTLS version $version])

        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this

        LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$gtlsprefix/lib$libsuff"
        export LD_LIBRARY_PATH
        AC_MSG_NOTICE([Added $gtlsprefix/lib$libsuff to LD_LIBRARY_PATH])
      fi

    fi

  fi dnl GNUTLS not disabled

fi dnl OPENSSL != 1

dnl ----------------------------------------------------
dnl NSS. Only check if GnuTLS and OpenSSL are not enabled
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for NSS files & libraries.
OPT_NSS=no

AC_ARG_WITH(nss,dnl
AC_HELP_STRING([--with-nss=PATH],[where to look for NSS, PATH points to the installation root (default: /usr/local/)])
AC_HELP_STRING([--without-nss], [disable NSS detection]),
  OPT_NSS=$withval)

if test "$OPENSSL_ENABLED" != "1" -a "$GNUTLS_ENABLED" != "1"; then

  if test X"$OPT_NSS" != Xno; then
    if test "x$OPT_NSS" = "xyes"; then
     check=`pkg-config --version 2>/dev/null`
     if test -n "$check"; then
       addlib=`pkg-config --libs nss`
       addcflags=`pkg-config --cflags nss`
       version=`pkg-config --modversion nss`
       nssprefix=`pkg-config --variable=prefix nss`
     fi
    else
      # Without pkg-config, we'll kludge in some defaults
      addlib="-lssl3 -lsmime3 -lnss3 -lplds4 -lplc4 -lnspr4 -lpthread -ldl"
      addcflags="-I$OPT_NSS/include"
      version="unknown"
      gtlsprefix=$OPT_GNUTLS
    fi

    dnl Check for functionPK11_CreateGenericObject
    dnl this is needed for using the PEM PKCS#11 module
    AC_CHECK_LIB(nss3, PK11_CreateGenericObject,
     [
     AC_DEFINE(HAVE_PK11_CREATEGENERICOBJECT, 1, [if you have the function PK11_CreateGenericObject])
     AC_SUBST(HAVE_PK11_CREATEGENERICOBJECT, [1])
     ])
    if test -n "$addlib"; then

      CLEANLIBS="$LIBS"
      CLEANCPPFLAGS="$CPPFLAGS"

      LIBS="$LIBS $addlib"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(nss3, NSS_Initialize,
       [
       AC_DEFINE(USE_NSS, 1, [if NSS is enabled])
       AC_SUBST(USE_NSS, [1])
       USE_NSS="yes"
       NSS_ENABLED=1
       curl_ssl_msg="enabled (NSS)"
       ],
       [
         LIBS="$CLEANLIBS"
         CPPFLAGS="$CLEANCPPFLAGS"
       ])

      if test "x$USE_NSS" = "xyes"; then
        AC_MSG_NOTICE([detected NSS version $version])

        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this

        LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$nssprefix/lib$libsuff"
        export LD_LIBRARY_PATH
        AC_MSG_NOTICE([Added $nssprefix/lib$libsuff to LD_LIBRARY_PATH])
      fi

    fi

  fi dnl NSS not disabled

fi dnl OPENSSL != 1 -a GNUTLS_ENABLED != 1

if test "x$OPENSSL_ENABLED$GNUTLS_ENABLED$NSS_ENABLED" = "x"; then
  AC_MSG_WARN([SSL disabled, you will not be able to use HTTPS, FTPS, NTLM and more.])
  AC_MSG_WARN([Use --with-ssl, --with-gnutls or --with-nss to address this.])
else
  # SSL is enabled, genericly
  AC_SUBST(SSL_ENABLED)
  SSL_ENABLED="1"
fi

dnl **********************************************************************
dnl Check for the CA bundle
dnl **********************************************************************

if test X"$SSL_ENABLED" != "X"; then

  AC_MSG_CHECKING([CA cert bundle install path])

  AC_ARG_WITH(ca-bundle,
AC_HELP_STRING([--with-ca-bundle=FILE], [File name to install the CA bundle as])
AC_HELP_STRING([--without-ca-bundle], [Don't install the CA bundle]),
    [ ca="$withval" ],
    [
      if test "x$prefix" != xNONE; then
        ca="\${prefix}/share/curl/curl-ca-bundle.crt"
      else
        ca="$ac_default_prefix/share/curl/curl-ca-bundle.crt"
      fi
    ] )

    if test "x$ca" != "xno"; then
      CURL_CA_BUNDLE='"'$ca'"'
      AC_SUBST(CURL_CA_BUNDLE)
    fi
    AC_MSG_RESULT([$ca])
fi dnl only done if some kind of SSL was enabled

AM_CONDITIONAL(CABUNDLE, test x$ca != xno)

dnl **********************************************************************
dnl Check for the presence of IDN libraries and headers
dnl **********************************************************************

AC_MSG_CHECKING([whether to build with libidn])
AC_ARG_WITH(libidn,
AC_HELP_STRING([--with-libidn=PATH],[Enable libidn usage])
AC_HELP_STRING([--without-libidn],[Disable libidn usage]),
  [LIBIDN="$withval"])

case "$LIBIDN" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)   AC_MSG_RESULT(yes)

       idn=""
       dnl if there is a given path, check that FIRST
       if test -n "$LIBIDN"; then
         if test "x$LIBIDN" != "xyes"; then
            oldLDFLAGS=$LDFLAGS
            oldCPPFLAGS=$CPPFLAGS
            LDFLAGS="$LDFLAGS -L$LIBIDN/lib"
            CPPFLAGS="$CPPFLAGS -I$LIBIDN/include"
            idn="yes"
            AC_CHECK_LIB(idn, idna_to_ascii_4i, ,
                         idn=""
                         LDFLAGS=$oldLDFLAGS
                         CPPFLAGS=$oldCPPFLAGS)
         fi
       fi

       if test "x$idn" != "xyes"; then
          dnl check with default paths
          idn="yes"
          AC_CHECK_LIB(idn, idna_to_ascii_lz, ,
                       idn="")
       fi

       if test "x$idn" = "xyes"; then
         curl_idn_msg="enabled"
         AC_SUBST(IDN_ENABLED, [1])
         dnl different versions of libidn have different setups of these:
         AC_CHECK_FUNCS( idn_free idna_strerror tld_strerror)
         AC_CHECK_HEADERS( idn-free.h tld.h )
       fi

       ;;
esac

dnl Default is to try the thread-safe versions of a few functions
OPT_THREAD=on

dnl detect AIX 4.3 or later
dnl see full docs on this reasoning in the lib/hostip.c source file
AC_MSG_CHECKING([AIX 4.3 or later])
AC_PREPROC_IFELSE([
#if defined(_AIX) && defined(_AIX43)
printf("just fine");
#else
#error "this is not AIX 4.3 or later"
#endif
],
 [ AC_MSG_RESULT([yes])
   RECENTAIX=yes
   OPT_THREAD=off ],
 [ AC_MSG_RESULT([no]) ]
)

AC_ARG_ENABLE(thread,dnl
AC_HELP_STRING([--disable-thread],[don't look for thread-safe functions])
AC_HELP_STRING([--enable-thread],[look for thread-safe functions]),
[ case "$enableval" in
  no)
    OPT_THREAD=off
    AC_MSG_WARN(libcurl will not get built using thread-safe functions)
    ;;
  *)
    ;;
  esac
]
)

if test X"$OPT_THREAD" = Xoff
then
  AC_DEFINE(DISABLED_THREADSAFE, 1,
    [Set to explicitly specify we don't want to use thread-safe functions])
else
  if test "$ipv6" != "yes"; then
    dnl dig around for gethostbyname_r()
    CURL_CHECK_GETHOSTBYNAME_R()

    dnl dig around for gethostbyaddr_r()
    dnl CURL_CHECK_GETHOSTBYADDR_R()
  fi

  dnl poke around for inet_ntoa_r()
  CURL_CHECK_INET_NTOA_R()

  dnl is there a localtime_r()
  CURL_CHECK_LOCALTIME_R()

  dnl is there a strerror_r()
  CURL_CHECK_STRERROR_R()

  checkfor_gmtime_r="yes"
fi

dnl for recent AIX versions, we skip all the thread-safe checks above since
dnl they claim a thread-safe libc using the standard API. But there are
dnl some functions still not thread-safe. Check for these!

dnl Let's hope this split URL remains working:
dnl http://publibn.boulder.ibm.com/doc_link/en_US/a_doc_lib/aixprggd/ \
dnl genprogc/thread_quick_ref.htm

if test "x$RECENTAIX" = "xyes"; then

  AC_DEFINE(_THREAD_SAFE, 1, [define this if you need it to compile thread-safe code])

  dnl check if this is the IMB xlc compiler
  dnl Details thanks to => http://predef.sourceforge.net/
  AC_MSG_CHECKING([if this is the xlc compiler])
  AC_EGREP_CPP([^__xlC__], [__xlC__],
         dnl action if the text is found, this it has not been replaced by the
         dnl cpp
         XLC="no"
         AC_MSG_RESULT([no]),
         dnl the text was not found, it was replaced by the cpp
         XLC="yes"
         AC_MSG_RESULT([yes])
         CFLAGS="$CFLAGS -qthreaded"
         dnl AIX xlc has to have strict aliasing turned off. If not,
         dnl the optimizer assumes that pointers can only point to
         dnl an object of the same type.
         CFLAGS="$CFLAGS -qnoansialias"
       )


  dnl is there a localtime_r()
  CURL_CHECK_LOCALTIME_R()

  dnl is there a strerror_r()
  CURL_CHECK_STRERROR_R()

  checkfor_gmtime_r="yes"
fi

if test x$cross_compiling != xyes; then

  if test x$checkfor_gmtime_r = xyes; then

    dnl if gmtime_r was found, verify that it actually works, as (at least) HPUX
    dnl 10.20 is known to have a buggy one. If it doesn't work, disable use of
    dnl it.

    AC_MSG_CHECKING([if gmtime_r exists and works])
    AC_RUN_IFELSE([[
    #include <time.h>
    int main(void)
    {
    time_t local = 1170352587;
    struct tm *gmt;
    struct tm keeper;
    putenv("TZ=CST6CDT");
    tzset();
    gmt = gmtime_r(&local, &keeper);
    if(gmt) {
      return 0;
    }
    return 1; /* failure */
    }
     ]],
     dnl success, do nothing
     AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_GMTIME_R, 1, [if you have (a working) gmtime_r])
     ,
     dnl failure, now disable the function
     AC_MSG_RESULT(no)
    ,
    dnl not invoked when crosscompiling)
     echo "hej"
    )
  fi
else
  dnl and for crosscompiling
  AC_CHECK_FUNCS(gmtime_r)
fi


dnl **********************************************************************
dnl Back to "normal" configuring
dnl **********************************************************************

dnl Checks for header files.
AC_HEADER_STDC

CURL_CHECK_HEADER_MALLOC

dnl Now check for the very most basic headers. Then we can use these
dnl ones as default-headers when checking for the rest!
AC_CHECK_HEADERS(
        sys/types.h \
        sys/time.h \
        sys/select.h \
        sys/socket.h \
        sys/ioctl.h \
        assert.h \
        unistd.h \
        stdlib.h \
        limits.h \
        arpa/inet.h \
        net/if.h \
        netinet/in.h \
        netinet/tcp.h \
        netdb.h \
        sys/sockio.h \
        sys/stat.h \
        sys/param.h \
        termios.h \
        termio.h \
        sgtty.h \
        fcntl.h \
        alloca.h \
        time.h \
        io.h \
        pwd.h \
        utime.h \
        sys/utime.h \
        sys/poll.h \
        poll.h \
        sys/resource.h \
        libgen.h \
        locale.h \
        errno.h \
        stdbool.h \
        arpa/tftp.h \
        sys/filio.h \
        setjmp.h,
dnl to do if not found
[],
dnl to do if found
[],
dnl default includes
[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
CURL_CHECK_VARIADIC_MACROS
AC_TYPE_SIZE_T
AC_HEADER_TIME
CURL_CHECK_STRUCT_TIMEVAL
CURL_VERIFY_RUNTIMELIBS

AC_CHECK_SIZEOF(curl_off_t, ,[
#include <stdio.h>
#include "$srcdir/include/curl/curl.h"
])
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(off_t)

AC_CHECK_TYPE(long long,
   [AC_DEFINE(HAVE_LONGLONG, 1, [if your compiler supports long long])]
   longlong="yes"
)

if test "xyes" = "x$longlong"; then
  AC_MSG_CHECKING([if numberLL works])
  AC_COMPILE_IFELSE([long long val = 1000LL;],
   [AC_DEFINE(HAVE_LL, 1, [if your compiler supports LL])]
   AC_MSG_RESULT(yes),
   AC_MSG_RESULT(no)
  )
fi


# check for ssize_t
AC_CHECK_TYPE(ssize_t, ,
   AC_DEFINE(ssize_t, int, [the signed version of size_t]))

# check for bool type
AC_CHECK_TYPE([bool],[
  AC_DEFINE(HAVE_BOOL_T, 1,
    [Define to 1 if bool is an available type.])
], ,[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
])

# Check for socklen_t or equivalent
CURL_CHECK_TYPE_SOCKLEN_T

TYPE_IN_ADDR_T

TYPE_SOCKADDR_STORAGE

TYPE_SIG_ATOMIC_T

AC_TYPE_SIGNAL

AC_FUNC_SELECT_ARGTYPES

CURL_CHECK_FUNC_RECV

CURL_CHECK_FUNC_SEND

CURL_CHECK_MSG_NOSIGNAL

dnl Checks for library functions.
dnl AC_PROG_GCC_TRADITIONAL

dnl AC_FUNC_VPRINTF
case $host in
  *msdosdjgpp)
     ac_cv_func_pipe=no
     skipcheck_pipe=yes
     AC_MSG_NOTICE([skip check for pipe on msdosdjgpp])
    ;;
esac
AC_CHECK_FUNCS( strtoll \
                socket \
                select \
                strdup \
                strstr \
                strcasestr \
                strtok_r \
                uname \
                strcasecmp \
                stricmp \
                strcmpi \
                gethostbyaddr \
                gettimeofday \
                inet_addr \
                inet_ntoa \
                inet_pton \
                perror \
                closesocket \
                siginterrupt \
                sigaction \
                signal \
                getpass_r \
                strlcat \
                getpwuid \
                geteuid \
                getppid \
                utime \
                sigsetjmp \
                basename \
                setlocale \
                ftruncate \
                pipe \
                poll \
                getprotobyname \
                getrlimit \
                setrlimit \
                fork \
                setmode,
dnl if found
[],
dnl if not found, $ac_func is the name we check for
func="$ac_func"
eval skipcheck=\$skipcheck_$func
if test "x$skipcheck" != "xyes"; then
  AC_MSG_CHECKING([deeper for $func])
  AC_TRY_LINK( [],
               [ $func ();],
               AC_MSG_RESULT(yes!)
               eval "ac_cv_func_$func=yes"
               def=`echo "HAVE_$func" | tr 'a-z' 'A-Z'`
               AC_DEFINE_UNQUOTED($def, 1, [If you have $func]),
               AC_MSG_RESULT(but still no)
               )
fi
)

dnl For some reason, the check above doesn't properly detect select() with
dnl Msys/Mingw
if test "$ac_cv_func_select" = "no"; then
  AC_MSG_CHECKING([for select in ws2_32])
  AC_TRY_LINK([
#undef inline
#ifdef HAVE_WINDOWS_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif
#endif
    ],[
      select(0,(fd_set *)NULL,(fd_set *)NULL,(fd_set *)NULL,(struct timeval *)NULL);
    ],[
      AC_MSG_RESULT([yes])
      HAVE_SELECT="1"
      AC_DEFINE_UNQUOTED(HAVE_SELECT, 1,
        [Define to 1 if you have the select function.])
    ],[
      AC_MSG_ERROR([You can't compile without a select])
  ])
fi

dnl sigsetjmp() might be a macro and no function so if it isn't found already
dnl we make an extra check here!
if test "$ac_cv_func_sigsetjmp" != "yes"; then
  AC_MSG_CHECKING([for sigsetjmp defined as macro])
  AC_TRY_LINK( [#include <setjmp.h>],
               [sigjmp_buf jmpenv;
                sigsetjmp(jmpenv, 1);],
               AC_MSG_RESULT(yes)
               AC_DEFINE(HAVE_SIGSETJMP, 1, [If you have sigsetjmp]),
               AC_MSG_RESULT(no)
               )
fi

AC_CHECK_DECL(basename, ,
              AC_DEFINE(NEED_BASENAME_PROTO, 1, [If you lack a fine basename() prototype]),
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
)

AC_CHECK_DECL(inet_pton, ,
              AC_DEFINE(HAVE_NO_INET_PTON_PROTO, 1,
                        [Defined if no inet_pton() prototype available]),
[
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
]
)

dnl Check if the getnameinfo function is available
dnl and get the types of five of its arguments.
CURL_CHECK_FUNC_GETNAMEINFO

if test "$ipv6" = "yes"; then
  CURL_CHECK_WORKING_GETADDRINFO
  CURL_CHECK_NI_WITHSCOPEID
fi

AC_MSG_CHECKING([if we are Mac OS X (to disable poll)])
disable_poll=no
case $host in
  *-*-darwin*)
    disable_poll="yes";
    ;;
  *)
    ;;
esac
AC_MSG_RESULT($disable_poll)

if test "$disable_poll" = "no"; then

  dnl poll() might be badly emulated, as in Mac OS X 10.3 (and other BSDs?) and
  dnl to find out we make an extra check here!
  if test "$ac_cv_func_poll" = "yes"; then
    AC_MSG_CHECKING([if poll works with NULL inputs])
    AC_RUN_IFELSE([
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif defined(HAVE_POLL_H)
#include <poll.h>
#endif

  int main(void)
  {
    /* make this return 0 == timeout since there's nothing to read from */
    return poll((void *)0, 0, 10 /*ms*/);
  }
],
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_POLL_FINE, 1, [If you have a fine poll]),
    AC_MSG_RESULT(no),
    AC_MSG_RESULT(cross-compiling assumes yes)
    AC_DEFINE(HAVE_POLL_FINE, 1, [If you have a fine poll])
    ) dnl end of AC_RUN_IFELSE
  fi dnl poll() was found
fi dnl poll()-check is not disabled


AC_PATH_PROG( PERL, perl, ,
  $PATH:/usr/local/bin/perl:/usr/bin/:/usr/local/bin )
AC_SUBST(PERL)

AC_PATH_PROGS( NROFF, gnroff nroff, ,
  $PATH:/usr/bin/:/usr/local/bin )
AC_SUBST(NROFF)

if test -n "$NROFF"; then
  dnl only check for nroff options if an nroff command was found

  AC_MSG_CHECKING([how to use *nroff to get plain text from man pages])
  MANOPT="-man"
  mancheck=`echo foo | $NROFF $MANOPT 2>/dev/null`
  if test -z "$mancheck"; then
    MANOPT="-mandoc"
   mancheck=`echo foo | $NROFF $MANOPT 2>/dev/null`
    if test -z "$mancheck"; then
      MANOPT=""
      AC_MSG_RESULT([failed])
      AC_MSG_WARN([found no *nroff option to get plaintext from man pages])
    else
      AC_MSG_RESULT([$MANOPT])
    fi
  else
    AC_MSG_RESULT([$MANOPT])
  fi
  AC_SUBST(MANOPT)
fi

if test -z "$MANOPT"
then
  dnl if no nroff tool was found, or no option that could convert man pages
  dnl was found, then disable the built-in manual stuff
  AC_MSG_WARN([disabling built-in manual])
  USE_MANUAL="no";
fi

dnl *************************************************************************
dnl If the manual variable still is set, then we go with providing a built-in
dnl manual

if test "$USE_MANUAL" = "1"; then
  AC_DEFINE(USE_MANUAL, 1, [If you want to build curl with the built-in manual])
  curl_manual_msg="enabled"
fi

dnl set variable for use in automakefile(s)
AM_CONDITIONAL(USE_MANUAL, test x"$USE_MANUAL" = x1)

AC_MSG_CHECKING([whether to enable c-ares])
AC_ARG_ENABLE(ares,
AC_HELP_STRING([--enable-ares=PATH],[Enable c-ares for name lookups])
AC_HELP_STRING([--disable-ares],[Disable c-ares for name lookups]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)   AC_MSG_RESULT(yes)

       if test "x$IPV6_ENABLED" = "x1"; then
         AC_MSG_NOTICE([c-ares may not work properly with ipv6])
       fi

       AC_DEFINE(USE_ARES, 1, [Define if you want to enable c-ares support])
       dnl substitute HAVE_ARES for curl-config and similar
       HAVE_ARES="1"
       AC_SUBST(HAVE_ARES)
       curl_ares_msg="enabled"

       LIBS="-lcares $LIBS"

       dnl For backwards compatibility default to includes/lib in srcdir/ares
       dnl If a value is specified it is assumed that the libs are in $val/lib
       dnl and the includes are in $val/include. This is the default setup for
       dnl ares so it should not be a problem.
       if test "x$enableval" = "xyes" ; then
         if test -d "$srcdir/ares"; then
            aresembedded="yes"
            AC_CONFIG_SUBDIRS(ares)
            aresinc=`cd $srcdir/ares && pwd`
            CPPFLAGS="$CPPFLAGS -I$aresinc"

            dnl the pwd= below cannot 'cd' into the ares dir to get the full
            dnl path to it, since it may not exist yet if we build outside of
            dnl the source tree
            pwd=`pwd`
            LDFLAGS="$LDFLAGS -L$pwd/ares"
         fi
       else
         CPPFLAGS="$CPPFLAGS -I$enableval/include"
         LDFLAGS="$LDFLAGS -L$enableval/lib"
       fi

       if test -z "$aresembedded"; then
         dnl verify that a sufficient c-ares is here if we have pointed one
         dnl out and don't use the "embedded" ares dir (in which case we don't
         dnl check it because it might not have been built yet)
         AC_MSG_CHECKING([that c-ares is good and recent enough])
         AC_LINK_IFELSE( [
#include <ares.h>
/* provide a set of dummy functions in case c-ares was built with debug */
void curl_dofree() { }
void curl_sclose() { }
void curl_domalloc() { }

int main(void)
{
  ares_channel channel;
  ares_cancel(channel); /* added in 1.2.0 */
  ares_process_fd(channel, 0, 0); /* added in 1.4.0 */
  return 0;
}
],
          AC_MSG_RESULT(yes),
          AC_MSG_RESULT(no)
          AC_MSG_ERROR([c-ares library defective or too old])
          )
       fi
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl ************************************************************
dnl disable verbose text strings
dnl
AC_MSG_CHECKING([whether to enable verbose strings])
AC_ARG_ENABLE(verbose,
AC_HELP_STRING([--enable-verbose],[Enable verbose strings])
AC_HELP_STRING([--disable-verbose],[Disable verbose strings]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_VERBOSE_STRINGS, 1, [to disable verbose strings])
       curl_verbose_msg="no"
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

CURL_CHECK_NATIVE_WINDOWS

dnl ************************************************************
dnl enable SSPI support
dnl
AC_MSG_CHECKING([whether to enable SSPI support (Windows native builds only)])
AC_ARG_ENABLE(sspi,
AC_HELP_STRING([--enable-sspi],[Enable SSPI])
AC_HELP_STRING([--disable-sspi],[Disable SSPI]),
[ case "$enableval" in
  yes)
       if test "$ac_cv_native_windows" = "yes"; then
         AC_MSG_RESULT(yes)
         AC_DEFINE(USE_WINDOWS_SSPI, 1, [to enable SSPI support])
         AC_SUBST(USE_WINDOWS_SSPI, [1])
         curl_sspi_msg="yes"
       else
         AC_MSG_RESULT(no)
         AC_MSG_WARN([--enable-sspi Ignored. Only supported on native Windows builds.])
       fi
       ;;
  *)
       AC_MSG_RESULT(no)
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl ************************************************************
dnl lame option to switch on debug options
dnl
AC_MSG_CHECKING([whether to enable debug options])
AC_ARG_ENABLE(debug,
AC_HELP_STRING([--enable-debug],[Enable pedantic debug options])
AC_HELP_STRING([--disable-debug],[Disable debug options]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)   AC_MSG_RESULT(yes)

    CPPFLAGS="$CPPFLAGS -DCURLDEBUG"
    CFLAGS="$CFLAGS -g"

    dnl set compiler "debug" options to become more picky, and remove
    dnl optimize options from CFLAGS
    CURL_CC_DEBUG_OPTS
       ;;
  esac
 ],
       AC_MSG_RESULT(no)
)

dnl ************************************************************
dnl disable cryptographic authentication
dnl
AC_MSG_CHECKING([whether to enable cryptographic authentication methods])
AC_ARG_ENABLE(crypto-auth,
AC_HELP_STRING([--enable-crypto-auth],[Enable cryptographic authentication])
AC_HELP_STRING([--disable-crypto-auth],[Disable cryptographic authentication]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_CRYPTO_AUTH, 1, [to disable cryptographic authentication])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable cookies support
dnl
AC_MSG_CHECKING([whether to enable support for cookies])
AC_ARG_ENABLE(cookies,
AC_HELP_STRING([--enable-cookies],[Enable cookies support])
AC_HELP_STRING([--disable-cookies],[Disable cookies support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_COOKIES, 1, [to disable cookies support])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl Enable hiding of internal symbols in library to reduce its size and
dnl speed dynamic linking of applications.  This currently is only supported
dnl on gcc >= 4.0 and SunPro C.
dnl
AC_MSG_CHECKING([whether to enable hidden symbols in the library])
AC_ARG_ENABLE(hidden-symbols,
AC_HELP_STRING([--enable-hidden-symbols],[Hide internal symbols in library])
AC_HELP_STRING([--disable-hidden-symbols],[Leave all symbols with default visibility in library]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ;;
  *)
       AC_MSG_CHECKING([whether $CC supports it])
       if test "$GCC" = yes ; then
         if $CC --help --verbose 2>&1 | grep fvisibility= > /dev/null ; then
           AC_MSG_RESULT(yes)
           AC_DEFINE(CURL_HIDDEN_SYMBOLS, 1, [to enable hidden symbols])
           AC_DEFINE(CURL_EXTERN_SYMBOL, [__attribute__ ((visibility ("default")))], [to make a symbol visible])
           CFLAGS="$CFLAGS -fvisibility=hidden"
         else
            AC_MSG_RESULT(no)
          fi

       else
         dnl Test for SunPro cc
         if $CC 2>&1 | grep flags >/dev/null && $CC -flags | grep xldscope= >/dev/null ; then
           AC_MSG_RESULT(yes)
           AC_DEFINE(CURL_HIDDEN_SYMBOLS, 1, [to enable hidden symbols])
           AC_DEFINE(CURL_EXTERN_SYMBOL, [__global], [to make a symbol visible])
           CFLAGS="$CFLAGS -xldscope=hidden"
         else
           AC_MSG_RESULT(no)
         fi
       fi
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl ************************************************************
if test "x$ws2" = "xyes"; then

  dnl If ws2_32 is wanted, make sure it is the _last_ lib in LIBS (makes
  dnl things work when built with c-ares). But we can't just move it last
  dnl since then other stuff (SSL) won't build. So we simply append it to the
  dnl end.

  LIBS="$LIBS -lws2_32"
  TEST_SERVER_LIBS="$TEST_SERVER_LIBS -lws2_32"

fi

dnl
dnl All the library dependencies put into $LIB apply to libcurl only.
dnl Those in $CURL_LIBS apply to the curl command-line client only.
dnl Those in $TEST_SERVER_LIBS apply to test servers only.
dnl Those in $ALL_LIBS apply to all targets, including test targets.
dnl
LIBCURL_LIBS=$LIBS

AC_SUBST(LIBCURL_LIBS)
AC_SUBST(CURL_LIBS)
AC_SUBST(TEST_SERVER_LIBS)
LIBS=$ALL_LIBS  dnl LIBS is a magic variable that's used for every link

AM_CONDITIONAL(CROSSCOMPILING, test x$cross_compiling = xyes)

AC_CONFIG_FILES([Makefile \
           docs/Makefile \
           docs/examples/Makefile \
           docs/libcurl/Makefile \
           include/Makefile \
           include/curl/Makefile \
           src/Makefile \
           lib/Makefile \
           tests/Makefile \
           tests/data/Makefile \
           tests/server/Makefile \
           tests/libtest/Makefile \
           packages/Makefile \
           packages/Win32/Makefile \
           packages/Win32/cygwin/Makefile \
           packages/Linux/Makefile \
           packages/Linux/RPM/Makefile \
           packages/Linux/RPM/curl.spec \
           packages/Linux/RPM/curl-ssl.spec \
           packages/Solaris/Makefile \
           packages/DOS/Makefile \
           packages/EPM/curl.list \
           packages/EPM/Makefile \
           packages/vms/Makefile \
           packages/AIX/Makefile \
           packages/AIX/RPM/Makefile \
           packages/AIX/RPM/curl.spec \
           curl-config \
           libcurl.pc
])
AC_OUTPUT

AC_MSG_NOTICE([Configured to build curl/libcurl:

  curl version:    ${VERSION}
  Host setup:      ${host}
  Install prefix:  ${prefix}
  Compiler:        ${CC}
  SSL support:     ${curl_ssl_msg}
  SSH support:     ${curl_ssh_msg}
  zlib support:    ${curl_zlib_msg}
  krb4 support:    ${curl_krb4_msg}
  GSSAPI support:  ${curl_gss_msg}
  SPNEGO support:  ${curl_spnego_msg}
  c-ares support:  ${curl_ares_msg}
  ipv6 support:    ${curl_ipv6_msg}
  IDN support:     ${curl_idn_msg}
  Build libcurl:   Shared=${enable_shared}, Static=${enable_static}
  Built-in manual: ${curl_manual_msg}
  Verbose errors:  ${curl_verbose_msg}
  SSPI support:    ${curl_sspi_msg}
  ca cert path:    ${ca}
  LDAP support:    ${curl_ldap_msg}
  LDAPS support:   ${curl_ldaps_msg}
])
