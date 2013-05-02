#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#***************************************************************************
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)

dnl We don't know the version number "statically" so we use a dash here
AC_INIT([curl], [-], [a suitable curl mailing list: http://curl.haxx.se/mail/])

XC_OVR_ZZ50
XC_OVR_ZZ60
CURL_OVERRIDE_AUTOCONF

dnl configure script copyright
AC_COPYRIGHT([Copyright (c) 1998 - 2013 Daniel Stenberg, <daniel@haxx.se>
This configure script may be copied, distributed and modified under the
terms of the curl license; see COPYING for more details])

AC_CONFIG_SRCDIR([lib/urldata.h])
AC_CONFIG_HEADERS(lib/curl_config.h include/curl/curlbuild.h)
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE

CURL_CHECK_OPTION_DEBUG
CURL_CHECK_OPTION_OPTIMIZE
CURL_CHECK_OPTION_WARNINGS
CURL_CHECK_OPTION_WERROR
CURL_CHECK_OPTION_CURLDEBUG
CURL_CHECK_OPTION_SYMBOL_HIDING
CURL_CHECK_OPTION_ARES

XC_CHECK_PATH_SEPARATOR

#
# save the configure arguments
#
CONFIGURE_OPTIONS="\"$ac_configure_args\""
AC_SUBST(CONFIGURE_OPTIONS)

CURL_CFLAG_EXTRAS=""
if test X"$want_werror" = Xyes; then
  CURL_CFLAG_EXTRAS="-Werror"
fi
AC_SUBST(CURL_CFLAG_EXTRAS)

dnl SED is mandatory for configure process and libtool.
dnl Set it now, allowing it to be changed later.
if test -z "$SED"; then
  dnl allow it to be overridden
  AC_PATH_PROG([SED], [sed], [not_found],
    [$PATH:/usr/bin:/usr/local/bin])
  if test -z "$SED" || test "$SED" = "not_found"; then
    AC_MSG_ERROR([sed not found in PATH. Cannot continue without sed.])
  fi
fi
AC_SUBST([SED])

dnl GREP is mandatory for configure process and libtool.
dnl Set it now, allowing it to be changed later.
if test -z "$GREP"; then
  dnl allow it to be overridden
  AC_PATH_PROG([GREP], [grep], [not_found],
    [$PATH:/usr/bin:/usr/local/bin])
  if test -z "$GREP" || test "$GREP" = "not_found"; then
    AC_MSG_ERROR([grep not found in PATH. Cannot continue without grep.])
  fi
fi
AC_SUBST([GREP])

dnl EGREP is mandatory for configure process and libtool.
dnl Set it now, allowing it to be changed later.
if test -z "$EGREP"; then
  dnl allow it to be overridden
  if echo a | ($GREP -E '(a|b)') >/dev/null 2>&1; then
    AC_MSG_CHECKING([for egrep])
    EGREP="$GREP -E"
    AC_MSG_RESULT([$EGREP])
  else
    AC_PATH_PROG([EGREP], [egrep], [not_found],
      [$PATH:/usr/bin:/usr/local/bin])
  fi
fi
if test -z "$EGREP" || test "$EGREP" = "not_found"; then
  AC_MSG_ERROR([egrep not found in PATH. Cannot continue without egrep.])
fi
AC_SUBST([EGREP])

dnl AR is mandatory for configure process and libtool.
dnl This is target dependent, so check it as a tool.
if test -z "$AR"; then
  dnl allow it to be overridden
  AC_PATH_TOOL([AR], [ar], [not_found],
    [$PATH:/usr/bin:/usr/local/bin])
  if test -z "$AR" || test "$AR" = "not_found"; then
    AC_MSG_ERROR([ar not found in PATH. Cannot continue without ar.])
  fi
fi
AC_SUBST([AR])

AC_SUBST(libext)

dnl Remove non-configure distributed curlbuild.h
if test -f ${srcdir}/include/curl/curlbuild.h; then
  rm -f ${srcdir}/include/curl/curlbuild.h
fi

dnl figure out the libcurl version
CURLVERSION=`$SED -ne 's/^#define LIBCURL_VERSION "\(.*\)"/\1/p' ${srcdir}/include/curl/curlver.h`
XC_CHECK_PROG_CC
AM_INIT_AUTOMAKE
AC_MSG_CHECKING([curl version])
AC_MSG_RESULT($CURLVERSION)

AC_SUBST(CURLVERSION)

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
    curl_ssl_msg="no      (--with-{ssl,gnutls,nss,polarssl,cyassl,axtls,winssl,darwinssl} )"
    curl_ssh_msg="no      (--with-libssh2)"
   curl_zlib_msg="no      (--with-zlib)"
   curl_krb4_msg="no      (--with-krb4*)"
    curl_gss_msg="no      (--with-gssapi)"
 curl_spnego_msg="no      (--with-spnego)"
curl_tls_srp_msg="no      (--enable-tls-srp)"
    curl_res_msg="default (--enable-ares / --enable-threaded-resolver)"
   curl_ipv6_msg="no      (--enable-ipv6)"
    curl_idn_msg="no      (--with-{libidn,winidn})"
 curl_manual_msg="no      (--enable-manual)"
curl_libcurl_msg="enabled (--disable-libcurl-option)"
curl_verbose_msg="enabled (--disable-verbose)"
   curl_sspi_msg="no      (--enable-sspi)"
   curl_ldap_msg="no      (--enable-ldap / --with-ldap-lib / --with-lber-lib)"
  curl_ldaps_msg="no      (--enable-ldaps)"
   curl_rtsp_msg="no      (--enable-rtsp)"
   curl_rtmp_msg="no      (--with-librtmp)"
  curl_mtlnk_msg="no      (--with-libmetalink)"

    init_ssl_msg=${curl_ssl_msg}

dnl
dnl Save some initial values the user might have provided
dnl
INITIAL_LDFLAGS=$LDFLAGS
INITIAL_LIBS=$LIBS

dnl
dnl Detect the canonical host and target build environment
dnl

AC_CANONICAL_HOST
dnl Get system canonical name
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

dnl Checks for programs.

dnl Our curl_off_t internal and external configure settings
CURL_CONFIGURE_CURL_OFF_T

dnl This defines _ALL_SOURCE for AIX
CURL_CHECK_AIX_ALL_SOURCE

dnl Our configure and build reentrant settings
CURL_CONFIGURE_THREAD_SAFE
CURL_CONFIGURE_REENTRANT

dnl check for how to do large files
AC_SYS_LARGEFILE

XC_LIBTOOL

#
# Automake conditionals based on libtool related checks
#

AM_CONDITIONAL([CURL_LT_SHLIB_USE_VERSION_INFO],
  [test "x$xc_lt_shlib_use_version_info" = 'xyes'])
AM_CONDITIONAL([CURL_LT_SHLIB_USE_NO_UNDEFINED],
  [test "x$xc_lt_shlib_use_no_undefined" = 'xyes'])
AM_CONDITIONAL([CURL_LT_SHLIB_USE_MIMPURE_TEXT],
  [test "x$xc_lt_shlib_use_mimpure_text" = 'xyes'])

#
# Due to libtool and automake machinery limitations of not allowing
# specifying separate CPPFLAGS or CFLAGS when compiling objects for
# inclusion of these in shared or static libraries, we are forced to
# build using separate configure runs for shared and static libraries
# on systems where different CPPFLAGS or CFLAGS are mandatory in order
# to compile objects for each kind of library. Notice that relying on
# the '-DPIC' CFLAG that libtool provides is not valid given that the
# user might for example choose to build static libraries with PIC.
#

#
# Make our Makefile.am files use the staticlib CPPFLAG only when strictly
# targeting a static library and not building its shared counterpart.
#

AM_CONDITIONAL([USE_CPPFLAG_CURL_STATICLIB],
  [test "x$xc_lt_build_static_only" = 'xyes'])

#
# Make staticlib CPPFLAG variable and its definition visible in output
# files unconditionally, providing an empty definition unless strictly
# targeting a static library and not building its shared counterpart.
#

CPPFLAG_CURL_STATICLIB=
if test "x$xc_lt_build_static_only" = 'xyes'; then
  CPPFLAG_CURL_STATICLIB='-DCURL_STATICLIB'
fi
AC_SUBST([CPPFLAG_CURL_STATICLIB])


# Determine whether all dependent libraries must be specified when linking
if test "X$enable_shared" = "Xyes" -a "X$link_all_deplibs" = "Xno"
then
    REQUIRE_LIB_DEPS=no
else
    REQUIRE_LIB_DEPS=yes
fi
AC_SUBST(REQUIRE_LIB_DEPS)
AM_CONDITIONAL(USE_EXPLICIT_LIB_DEPS, test x$REQUIRE_LIB_DEPS = xyes)

dnl check if there's a way to force code inline
AC_C_INLINE

dnl **********************************************************************
dnl platform/compiler/architecture specific checks/flags
dnl **********************************************************************

CURL_CHECK_COMPILER
CURL_SET_COMPILER_BASIC_OPTS
CURL_SET_COMPILER_DEBUG_OPTS
CURL_SET_COMPILER_OPTIMIZE_OPTS
CURL_SET_COMPILER_WARNING_OPTS

if test "$compiler_id" = "INTEL_UNIX_C"; then
  #
  if test "$compiler_num" -ge "1000"; then
    dnl icc 10.X or later
    CFLAGS="$CFLAGS -shared-intel"
  elif test "$compiler_num" -ge "900"; then
    dnl icc 9.X specific
    CFLAGS="$CFLAGS -i-dynamic"
  fi
  #
fi

CURL_CHECK_COMPILER_HALT_ON_ERROR
CURL_CHECK_COMPILER_ARRAY_SIZE_NEGATIVE
CURL_CHECK_COMPILER_PROTOTYPE_MISMATCH
CURL_CHECK_COMPILER_SYMBOL_HIDING

CURL_CHECK_CURLDEBUG
AM_CONDITIONAL(CURLDEBUG, test x$want_curldebug = xyes)

supports_unittests=yes
# cross-compilation of unit tests static library/programs fails when
# libcurl shared library is built. This might be due to a libtool or
# automake issue. In this case we disable unit tests.
if test "x$cross_compiling" != "xno" &&
   test "x$enable_shared" != "xno"; then
  supports_unittests=no
fi

# IRIX 6.5.24 gcc 3.3 autobuilds fail unittests library compilation due to
# a problem related with OpenSSL headers and library versions not matching.
# Disable unit tests while time to further investigate this is found.
case $host in
  mips-sgi-irix6.5)
    if test "$compiler_id" = "GNU_C"; then
      supports_unittests=no
    fi
    ;;
esac

# All AIX autobuilds fails unit tests linking against unittests library
# due to unittests library being built with no symbols or members. Libtool ?
# Disable unit tests while time to further investigate this is found.
case $host_os in
  aix*)
    supports_unittests=no
    ;;
esac

dnl Build unit tests when option --enable-debug is given.
if test "x$want_debug" = "xyes" &&
   test "x$supports_unittests" = "xyes"; then
  want_unittests=yes
else
  want_unittests=no
fi
AM_CONDITIONAL(BUILD_UNITTESTS, test x$want_unittests = xyes)

dnl **********************************************************************
dnl Compilation based checks should not be done before this point.
dnl **********************************************************************

dnl **********************************************************************
dnl Make sure that our checks for headers windows.h winsock.h winsock2.h
dnl and ws2tcpip.h take precedence over any other further checks which
dnl could be done later using AC_CHECK_HEADER or AC_CHECK_HEADERS for
dnl this specific header files. And do them before its results are used.
dnl **********************************************************************

CURL_CHECK_HEADER_WINDOWS
CURL_CHECK_NATIVE_WINDOWS
case X-"$ac_cv_native_windows" in
  X-yes)
    CURL_CHECK_HEADER_WINSOCK
    CURL_CHECK_HEADER_WINSOCK2
    CURL_CHECK_HEADER_WS2TCPIP
    CURL_CHECK_HEADER_WINLDAP
    CURL_CHECK_HEADER_WINBER
    ;;
  *)
    ac_cv_header_winsock_h="no"
    ac_cv_header_winsock2_h="no"
    ac_cv_header_ws2tcpip_h="no"
    ac_cv_header_winldap_h="no"
    ac_cv_header_winber_h="no"
    ;;
esac
CURL_CHECK_WIN32_LARGEFILE

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
       AC_MSG_WARN([disable HTTP disables FTP over proxy and RTSP])
       AC_SUBST(CURL_DISABLE_HTTP, [1])
       AC_DEFINE(CURL_DISABLE_RTSP, 1, [to disable RTSP])
       AC_SUBST(CURL_DISABLE_RTSP, [1])
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
       AC_MSG_RESULT(yes)
       ;;
  esac ],[
       AC_MSG_RESULT(yes) ]
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
  *)   if test "x$CURL_DISABLE_LDAP" = "x1" ; then
         AC_MSG_RESULT(LDAP needs to be enabled to support LDAPS)
         AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
         AC_SUBST(CURL_DISABLE_LDAPS, [1])
       else
         AC_MSG_RESULT(yes)
         AC_DEFINE(HAVE_LDAP_SSL, 1, [Use LDAPS implementation])
         AC_SUBST(HAVE_LDAP_SSL, [1])
       fi
       ;;
  esac ],[
       if test "x$CURL_DISABLE_LDAP" = "x1" ; then
         AC_MSG_RESULT(no)
         AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
         AC_SUBST(CURL_DISABLE_LDAPS, [1])
       else
         AC_MSG_RESULT(yes)
         AC_DEFINE(HAVE_LDAP_SSL, 1, [Use LDAPS implementation])
         AC_SUBST(HAVE_LDAP_SSL, [1])
       fi ]
)

AC_MSG_CHECKING([whether to support rtsp])
AC_ARG_ENABLE(rtsp,
AC_HELP_STRING([--enable-rtsp],[Enable RTSP support])
AC_HELP_STRING([--disable-rtsp],[Disable RTSP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_RTSP, 1, [to disable RTSP])
       AC_SUBST(CURL_DISABLE_RTSP, [1])
       ;;
  *)   if test x$CURL_DISABLE_HTTP = x1 ; then
          AC_MSG_ERROR(HTTP support needs to be enabled in order to enable RTSP support!)
       else
          AC_MSG_RESULT(yes)
          curl_rtsp_msg="enabled"
       fi
       ;;
  esac ],
       if test "x$CURL_DISABLE_HTTP" != "x1"; then
          AC_MSG_RESULT(yes)
          curl_rtsp_msg="enabled"
       else
          AC_MSG_RESULT(no)
       fi
)

AC_MSG_CHECKING([whether to support proxies])
AC_ARG_ENABLE(proxy,
AC_HELP_STRING([--enable-proxy],[Enable proxy support])
AC_HELP_STRING([--disable-proxy],[Disable proxy support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_PROXY, 1, [to disable proxies])
       AC_SUBST(CURL_DISABLE_PROXY, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
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

AC_MSG_CHECKING([whether to support pop3])
AC_ARG_ENABLE(pop3,
AC_HELP_STRING([--enable-pop3],[Enable POP3 support])
AC_HELP_STRING([--disable-pop3],[Disable POP3 support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_POP3, 1, [to disable POP3])
       AC_SUBST(CURL_DISABLE_POP3, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)


AC_MSG_CHECKING([whether to support imap])
AC_ARG_ENABLE(imap,
AC_HELP_STRING([--enable-imap],[Enable IMAP support])
AC_HELP_STRING([--disable-imap],[Disable IMAP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_IMAP, 1, [to disable IMAP])
       AC_SUBST(CURL_DISABLE_IMAP, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)


AC_MSG_CHECKING([whether to support smtp])
AC_ARG_ENABLE(smtp,
AC_HELP_STRING([--enable-smtp],[Enable SMTP support])
AC_HELP_STRING([--disable-smtp],[Disable SMTP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_SMTP, 1, [to disable SMTP])
       AC_SUBST(CURL_DISABLE_SMTP, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

AC_MSG_CHECKING([whether to support gopher])
AC_ARG_ENABLE(gopher,
AC_HELP_STRING([--enable-gopher],[Enable Gopher support])
AC_HELP_STRING([--disable-gopher],[Disable Gopher support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_GOPHER, 1, [to disable Gopher])
       AC_SUBST(CURL_DISABLE_GOPHER, [1])
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

dnl ************************************************************
dnl disable C code generation support
dnl
AC_MSG_CHECKING([whether to enable generation of C code])
AC_ARG_ENABLE(libcurl_option,
AC_HELP_STRING([--enable-libcurl-option],[Enable --libcurl C code generation support])
AC_HELP_STRING([--disable-libcurl-option],[Disable --libcurl C code generation support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_LIBCURL_OPTION, 1, [to disable --libcurl C code generation option])
       curl_libcurl_msg="no"
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl **********************************************************************
dnl Checks for libraries.
dnl **********************************************************************

AC_MSG_CHECKING([whether to use libgcc])
AC_ARG_ENABLE(libgcc,
AC_HELP_STRING([--enable-libgcc],[use libgcc when linking]),
[ case "$enableval" in
  yes)
       LIBS="-lgcc $LIBS"
       AC_MSG_RESULT(yes)
       ;;
  *)   AC_MSG_RESULT(no)
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

CURL_CHECK_LIB_XNET

dnl gethostbyname without lib or in the nsl lib?
AC_CHECK_FUNC(gethostbyname,
              [HAVE_GETHOSTBYNAME="1"
              ],
              [ AC_CHECK_LIB(nsl, gethostbyname,
                             [HAVE_GETHOSTBYNAME="1"
                             LIBS="-lnsl $LIBS"
                             ])
              ])

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the socket lib?
  AC_CHECK_LIB(socket, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="-lsocket $LIBS"
               ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the watt lib?
  AC_CHECK_LIB(watt, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               CPPFLAGS="-I/dev/env/WATT_ROOT/inc"
               LDFLAGS="-L/dev/env/WATT_ROOT/lib"
               LIBS="-lwatt $LIBS"
               ])
fi

dnl At least one system has been identified to require BOTH nsl and socket
dnl libs at the same time to link properly.
if test "$HAVE_GETHOSTBYNAME" != "1"
then
  AC_MSG_CHECKING([for gethostbyname with both nsl and socket libs])
  my_ac_save_LIBS=$LIBS
  LIBS="-lnsl -lsocket $LIBS"
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      gethostbyname();
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
    LIBS=$my_ac_save_LIBS
  ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for winsock systems
  if test "$ac_cv_header_windows_h" = "yes"; then
    if test "$ac_cv_header_winsock_h" = "yes"; then
      case $host in
        *-*-mingw32ce*)
          winsock_LIB="-lwinsock"
          ;;
        *)
          winsock_LIB="-lwsock32"
          ;;
      esac
    fi
    if test "$ac_cv_header_winsock2_h" = "yes"; then
      winsock_LIB="-lws2_32"
    fi
    if test ! -z "$winsock_LIB"; then
      my_ac_save_LIBS=$LIBS
      LIBS="$winsock_LIB $LIBS"
      AC_MSG_CHECKING([for gethostbyname in $winsock_LIB])
      AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
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
        ]],[[
          gethostbyname("www.dummysite.com");
        ]])
      ],[
        AC_MSG_RESULT([yes])
        HAVE_GETHOSTBYNAME="1"
      ],[
        AC_MSG_RESULT([no])
        winsock_LIB=""
        LIBS=$my_ac_save_LIBS
      ])
    fi
  fi
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for Minix 3.1
  AC_MSG_CHECKING([for gethostbyname for Minix 3])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
/* Older Minix versions may need <net/gen/netdb.h> here instead */
#include <netdb.h>
    ]],[[
      gethostbyname("www.dummysite.com");
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
  ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl This is for eCos with a stubbed DNS implementation
  AC_MSG_CHECKING([for gethostbyname for eCos])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
#include <stdio.h>
#include <netdb.h>
    ]],[[
      gethostbyname("www.dummysite.com");
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
  ],[
    AC_MSG_RESULT([no])
  ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the network lib - for Haiku OS
  AC_CHECK_LIB(network, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="-lnetwork $LIBS"
               ])
fi

if test "$HAVE_GETHOSTBYNAME" != "1"
then
  dnl gethostbyname in the net lib - for BeOS
  AC_CHECK_LIB(net, gethostbyname,
               [HAVE_GETHOSTBYNAME="1"
               LIBS="-lnet $LIBS"
               ])
fi


if test "$HAVE_GETHOSTBYNAME" != "1"; then
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
ac_cv_func_strcasecmp="no"

CURL_CHECK_LIBS_CONNECT

CURL_NETWORK_LIBS=$LIBS

dnl **********************************************************************
dnl In case that function clock_gettime with monotonic timer is available,
dnl check for additional required libraries.
dnl **********************************************************************
CURL_CHECK_LIBS_CLOCK_GETTIME_MONOTONIC

dnl **********************************************************************
dnl The preceding library checks are all potentially useful for test
dnl servers and libtest cases which require networking and clock_gettime
dnl support.  Save the list of required libraries at this point for use
dnl while linking those test servers and programs.
dnl **********************************************************************
CURL_NETWORK_AND_TIME_LIBS=$LIBS

dnl **********************************************************************
dnl Check for the presence of ZLIB libraries and headers
dnl **********************************************************************

dnl Check for & handle argument to --with-zlib.

clean_CPPFLAGS=$CPPFLAGS
clean_LDFLAGS=$LDFLAGS
clean_LIBS=$LIBS
ZLIB_LIBS=""
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
                   [HAVE_LIBZ="1"
                    LIBS="-lz $LIBS"],
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
                   LIBS="-lz $LIBS"
                   ],
                   [ CPPFLAGS=$clean_CPPFLAGS
                   LDFLAGS=$clean_LDFLAGS])
    fi
    ],
    [
      dnl zlib.h was not found, restore the flags
      CPPFLAGS=$clean_CPPFLAGS
      LDFLAGS=$clean_LDFLAGS]
    )

  if test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" != "1"
  then
    AC_MSG_WARN([configure found only the libz lib, not the header file!])
    HAVE_LIBZ=""
    CPPFLAGS=$clean_CPPFLAGS
    LDFLAGS=$clean_LDFLAGS
    LIBS=$clean_LIBS
  elif test "$HAVE_LIBZ" != "1" && test "$HAVE_ZLIB_H" = "1"
  then
    AC_MSG_WARN([configure found only the libz header file, not the lib!])
    CPPFLAGS=$clean_CPPFLAGS
    LDFLAGS=$clean_LDFLAGS
    LIBS=$clean_LIBS
  elif test "$HAVE_LIBZ" = "1" && test "$HAVE_ZLIB_H" = "1"
  then
    dnl both header and lib were found!
    AC_SUBST(HAVE_LIBZ)
    AC_DEFINE(HAVE_ZLIB_H, 1, [if you have the zlib.h header file])
    AC_DEFINE(HAVE_LIBZ, 1, [if zlib is available])

    ZLIB_LIBS="-lz"
    LIBS="-lz $clean_LIBS"

    dnl replace 'HAVE_LIBZ' in the automake makefile.ams
    AMFIXLIB="1"
    AC_MSG_NOTICE([found both libz and libz.h header])
    curl_zlib_msg="enabled"
  fi
fi

dnl set variable for use in automakefile(s)
AM_CONDITIONAL(HAVE_LIBZ, test x"$AMFIXLIB" = x1)
AC_SUBST(ZLIB_LIBS)

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
    if test "$ac_cv_native_windows" = "yes"; then
      dnl Windows uses a single and unique LDAP library name
      LDAPLIBNAME="wldap32"
      LBERLIBNAME="no"
    fi
  fi

  if test "$LDAPLIBNAME" ; then
    AC_CHECK_LIB("$LDAPLIBNAME", ldap_init,, [
      AC_MSG_WARN(["$LDAPLIBNAME" is not an LDAP library: LDAP disabled])
      AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
      AC_SUBST(CURL_DISABLE_LDAP, [1])
      AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
      AC_SUBST(CURL_DISABLE_LDAPS, [1])])
  else
    dnl Try to find the right ldap libraries for this system
    CURL_CHECK_LIBS_LDAP
    case X-"$curl_cv_ldap_LIBS" in
      X-unknown)
        AC_MSG_WARN([Cannot find libraries for LDAP support: LDAP disabled])
        AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
        AC_SUBST(CURL_DISABLE_LDAP, [1])
        AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
        AC_SUBST(CURL_DISABLE_LDAPS, [1])
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
        AC_SUBST(CURL_DISABLE_LDAP, [1])
        AC_DEFINE(CURL_DISABLE_LDAPS, 1, [to disable LDAPS])
        AC_SUBST(CURL_DISABLE_LDAPS, [1])])
    fi
  fi
fi

if test x$CURL_DISABLE_LDAP != x1 ; then
  AC_CHECK_FUNCS([ldap_url_parse ldap_init_fd])

  if test "$LDAPLIBNAME" = "wldap32"; then
    curl_ldap_msg="enabled (winldap)"
    AC_DEFINE(CURL_LDAP_WIN, 1, [Use Windows LDAP implementation])
  else
    curl_ldap_msg="enabled (OpenLDAP)"
    if test "x$ac_cv_func_ldap_init_fd" = "xyes"; then
      AC_DEFINE(USE_OPENLDAP, 1, [Use OpenLDAP-specific code])
      AC_SUBST(USE_OPENLDAP, [1])
    fi
  fi
fi

if test x$CURL_DISABLE_LDAPS != x1 ; then
    curl_ldaps_msg="enabled"
fi

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

# Check if struct sockaddr_in6 have sin6_scope_id member
if test "$ipv6" = yes; then
  AC_MSG_CHECKING([if struct sockaddr_in6 has sin6_scope_id member])
  AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>] ,
  struct sockaddr_in6 s; s.sin6_scope_id = 0; , have_sin6_scope_id=yes)
  if test "$have_sin6_scope_id" = yes; then
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID, 1, [Define to 1 if struct sockaddr_in6 has the sin6_scope_id member])
  else
    AC_MSG_RESULT([no])
  fi
fi

dnl **********************************************************************
dnl Check if the operating system allows programs to write to their own argv[]
dnl **********************************************************************

AC_MSG_CHECKING([if argv can be written to])
AC_RUN_IFELSE([
  AC_LANG_SOURCE([[
int main(int argc, char ** argv) {
    argv[0][0] = ' ';
    return (argv[0][0] == ' ')?0:1;
}
  ]])
],[
  curl_cv_writable_argv=yes
],[
  curl_cv_writable_argv=no
],[
  curl_cv_writable_argv=cross
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
     elif test "$GSSAPI_ROOT" != "yes"; then
        GSSAPI_INCS="-I$GSSAPI_ROOT/include"
     fi
  fi

  CPPFLAGS="$CPPFLAGS $GSSAPI_INCS"

  AC_CHECK_HEADER(gss.h,
    [
      dnl found in the given dirs
      AC_DEFINE(HAVE_GSSGNU, 1, [if you have the GNU gssapi libraries])
      gnu_gss=yes
    ],
    [
      dnl not found, check Heimdal or MIT
      AC_CHECK_HEADERS([gssapi/gssapi.h], [], [not_mit=1])
      AC_CHECK_HEADERS(
        [gssapi/gssapi_generic.h gssapi/gssapi_krb5.h],
        [],
        [not_mit=1],
        [
AC_INCLUDES_DEFAULT
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#endif
        ])
      if test "x$not_mit" = "x1"; then
        dnl MIT not found, check for Heimdal
        AC_CHECK_HEADER(gssapi.h,
            [
              dnl found
              AC_DEFINE(HAVE_GSSHEIMDAL, 1, [if you have the Heimdal gssapi libraries])
            ],
            [
              dnl no header found, disabling GSS
              want_gss=no
              AC_MSG_WARN(disabling GSSAPI since no header files was found)
            ]
          )
      else
        dnl MIT found
        AC_DEFINE(HAVE_GSSMIT, 1, [if you have the MIT gssapi libraries])
        dnl check if we have a really old MIT kerberos (<= 1.2)
        AC_MSG_CHECKING([if gssapi headers declare GSS_C_NT_HOSTBASED_SERVICE])
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
          ]],[[
            gss_import_name(
                            (OM_uint32 *)0,
                            (gss_buffer_t)0,
                            GSS_C_NT_HOSTBASED_SERVICE,
                            (gss_name_t *)0);
          ]])
        ],[
          AC_MSG_RESULT([yes])
        ],[
          AC_MSG_RESULT([no])
          AC_DEFINE(HAVE_OLD_GSSMIT, 1,
            [if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE])
        ])
      fi
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
    LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR"
    LIBS="-lgss $LIBS"
  elif test -z "$GSSAPI_LIB_DIR"; then
     case $host in
     *-*-darwin*)
        LIBS="-lgssapi_krb5 -lresolv $LIBS"
        ;;
     *)
        if test -f "$GSSAPI_ROOT/bin/krb5-config"; then
           dnl krb5-config doesn't have --libs-only-L or similar, put everything
           dnl into LIBS
           gss_libs=`$GSSAPI_ROOT/bin/krb5-config --libs gssapi`
           LIBS="$gss_libs $LIBS"
        elif test "$GSSAPI_ROOT" != "yes"; then
           LDFLAGS="$LDFLAGS -L$GSSAPI_ROOT/lib$libsuff"
           LIBS="-lgssapi $LIBS"
        else
           LIBS="-lgssapi $LIBS"
        fi
        ;;
     esac
  else
     LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR"
     LIBS="-lgssapi $LIBS"
  fi
else
  CPPFLAGS="$save_CPPFLAGS"
fi

dnl -------------------------------------------------
dnl check winssl option before other SSL libraries
dnl -------------------------------------------------

OPT_WINSSL=no
AC_ARG_WITH(winssl,dnl
AC_HELP_STRING([--with-winssl],[enable Windows native SSL/TLS])
AC_HELP_STRING([--without-winssl], [disable Windows native SSL/TLS]),
  OPT_WINSSL=$withval)

AC_MSG_CHECKING([whether to enable Windows native SSL/TLS (Windows native builds only)])
if test "$curl_ssl_msg" = "$init_ssl_msg"; then
  if test "x$OPT_WINSSL" != "xno"  &&
     test "x$ac_cv_native_windows" = "xyes"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_SCHANNEL, 1, [to enable Windows native SSL/TLS support])
    AC_SUBST(USE_SCHANNEL, [1])
    curl_ssl_msg="enabled (Windows-native)"
    WINSSL_ENABLED=1
    # --with-winssl implies --enable-sspi
    AC_DEFINE(USE_WINDOWS_SSPI, 1, [to enable SSPI support])
    AC_SUBST(USE_WINDOWS_SSPI, [1])
    curl_sspi_msg="enabled"
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

OPT_DARWINSSL=no
AC_ARG_WITH(darwinssl,dnl
AC_HELP_STRING([--with-darwinssl],[enable iOS/Mac OS X native SSL/TLS])
AC_HELP_STRING([--without-darwinssl], [disable iOS/Mac OS X native SSL/TLS]),
  OPT_DARWINSSL=$withval)

AC_MSG_CHECKING([whether to enable iOS/Mac OS X native SSL/TLS])
if test "$curl_ssl_msg" = "$init_ssl_msg"; then
  if test "x$OPT_DARWINSSL" != "xno" &&
     test -d "/System/Library/Frameworks/Security.framework"; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(USE_DARWINSSL, 1, [to enable iOS/Mac OS X native SSL/TLS support])
    AC_SUBST(USE_DARWINSSL, [1])
    curl_ssl_msg="enabled (iOS/Mac OS X-native)"
    DARWINSSL_ENABLED=1
    LDFLAGS="$LDFLAGS -framework CoreFoundation -framework Security"
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
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

if test "$curl_ssl_msg" = "$init_ssl_msg" && test X"$OPT_SSL" != Xno; then
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

    dnl Try pkg-config even when cross-compiling.  Since we
    dnl specify PKG_CONFIG_LIBDIR we're only looking where
    dnl the user told us to look
    OPENSSL_PCDIR="$OPT_SSL/lib/pkgconfig"
    AC_MSG_NOTICE([PKG_CONFIG_LIBDIR will be set to "$OPENSSL_PCDIR"])
    if test -f "$OPENSSL_PCDIR/openssl.pc"; then
      PKGTEST="yes"
    fi

    dnl in case pkg-config comes up empty, use what we got
    dnl via --with-ssl
    LIB_OPENSSL="$PREFIX_OPENSSL/lib$libsuff"
    if test "$PREFIX_OPENSSL" != "/usr" ; then
      SSL_LDFLAGS="-L$LIB_OPENSSL"
      SSL_CPPFLAGS="-I$PREFIX_OPENSSL/include"
    fi
    SSL_CPPFLAGS="$SSL_CPPFLAGS -I$PREFIX_OPENSSL/include/openssl"
    ;;
  esac

  if test "$PKGTEST" = "yes"; then

    CURL_CHECK_PKGCONFIG(openssl, [$OPENSSL_PCDIR])

    if test "$PKGCONFIG" != "no" ; then
      SSL_LIBS=`CURL_EXPORT_PCDIR([$OPENSSL_PCDIR]) dnl
        $PKGCONFIG --libs-only-l openssl 2>/dev/null`

      SSL_LDFLAGS=`CURL_EXPORT_PCDIR([$OPENSSL_PCDIR]) dnl
        $PKGCONFIG --libs-only-L openssl 2>/dev/null`

      SSL_CPPFLAGS=`CURL_EXPORT_PCDIR([$OPENSSL_PCDIR]) dnl
        $PKGCONFIG --cflags-only-I openssl 2>/dev/null`

      AC_MSG_NOTICE([pkg-config: SSL_LIBS: "$SSL_LIBS"])
      AC_MSG_NOTICE([pkg-config: SSL_LDFLAGS: "$SSL_LDFLAGS"])
      AC_MSG_NOTICE([pkg-config: SSL_CPPFLAGS: "$SSL_CPPFLAGS"])

      LIB_OPENSSL=`echo $SSL_LDFLAGS | sed -e 's/-L//g'`

      dnl use the values pkg-config reported.  This is here
      dnl instead of below with CPPFLAGS and LDFLAGS because we only
      dnl learn about this via pkg-config.  If we only have
      dnl the argument to --with-ssl we don't know what
      dnl additional libs may be necessary.  Hope that we
      dnl don't need any.
      LIBS="$SSL_LIBS $LIBS"
    fi
  fi

  dnl finally, set flags to use SSL
  CPPFLAGS="$CPPFLAGS $SSL_CPPFLAGS"
  LDFLAGS="$LDFLAGS $SSL_LDFLAGS"

  dnl This is for Msys/Mingw
  case $host in
    *-*-msys* | *-*-mingw*)
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
        LIBS="-lRSAglue -lrsaref $LIBS"
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
                    ENGINE_cleanup \
                    CRYPTO_cleanup_all_ex_data \
                    SSL_get_shutdown \
                    SSLv2_client_method )

    dnl Make an attempt to detect if this is actually yassl's headers and
    dnl OpenSSL emulation layer. We still leave everything else believing
    dnl and acting like OpenSSL.

    AC_MSG_CHECKING([for yaSSL using OpenSSL compatibility mode])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <openssl/ssl.h>
      ]],[[
#if defined(YASSL_VERSION) && defined(OPENSSL_VERSION_NUMBER)
        int dummy = SSL_ERROR_NONE;
#else
        Not the yaSSL OpenSSL compatibility header.
#endif
      ]])
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
       if test "x$cross_compiling" != "xyes"; then
         LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$LIB_OPENSSL"
         export LD_LIBRARY_PATH
         AC_MSG_NOTICE([Added $LIB_OPENSSL to LD_LIBRARY_PATH])
       fi
    fi
    CURL_CHECK_OPENSSL_API
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
          if test x$cross_compiling != xyes; then
            dnl Check for random device
            AC_CHECK_FILE("/dev/urandom", [ RANDOM_FILE="/dev/urandom"] )
          else
            AC_MSG_WARN([skipped the /dev/urandom detection when cross-compiling])
          fi
      ]
  )
  if test -n "$RANDOM_FILE" && test X"$RANDOM_FILE" != Xno ; then
          AC_SUBST(RANDOM_FILE)
          AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE",
          [a suitable file to read random data from])
  fi
fi

dnl ---
dnl We require OpenSSL with SRP support.
dnl ---
if test "$OPENSSL_ENABLED" = "1"; then
  AC_CHECK_LIB(crypto, SRP_Calc_client_key,
   [
     AC_DEFINE(HAVE_SSLEAY_SRP, 1, [if you have the function SRP_Calc_client_key])
     AC_SUBST(HAVE_SSLEAY_SRP, [1])
   ])
fi

dnl ----------------------------------------------------
dnl check for GnuTLS
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for GnuTLS files & libraries.
OPT_GNUTLS=no

AC_ARG_WITH(gnutls,dnl
AC_HELP_STRING([--with-gnutls=PATH],[where to look for GnuTLS, PATH points to the installation root])
AC_HELP_STRING([--without-gnutls], [disable GnuTLS detection]),
  OPT_GNUTLS=$withval)

if test "$curl_ssl_msg" = "$init_ssl_msg"; then

  if test X"$OPT_GNUTLS" != Xno; then

    addld=""
    addlib=""
    gtlslib=""
    version=""
    addcflags=""

    if test "x$OPT_GNUTLS" = "xyes"; then
      dnl this is with no partiular path given
      CURL_CHECK_PKGCONFIG(gnutls)

      if test "$PKGCONFIG" != "no" ; then
        addlib=`$PKGCONFIG --libs-only-l gnutls`
        addld=`$PKGCONFIG --libs-only-L gnutls`
        addcflags=`$PKGCONFIG --cflags-only-I gnutls`
        version=`$PKGCONFIG --modversion gnutls`
        gtlslib=`echo $addld | $SED -e 's/-L//'`
      else
        dnl without pkg-config, we try libgnutls-config as that was how it
        dnl used to be done
        check=`libgnutls-config --version 2>/dev/null`
        if test -n "$check"; then
          addlib=`libgnutls-config --libs`
          addcflags=`libgnutls-config --cflags`
          version=`libgnutls-config --version`
          gtlslib=`libgnutls-config --prefix`/lib$libsuff
        fi
      fi
    else
      dnl this is with a given path, first check if there's a libgnutls-config
      dnl there and if not, make an educated guess
      cfg=$OPT_GNUTLS/bin/libgnutls-config
      check=`$cfg --version 2>/dev/null`
      if test -n "$check"; then
        addlib=`$cfg --libs`
        addcflags=`$cfg --cflags`
        version=`$cfg --version`
        gtlslib=`$cfg --prefix`/lib$libsuff
      else
        dnl without pkg-config and libgnutls-config, we guess a lot!
        addlib=-lgnutls
        addld=-L$OPT_GNUTLS/lib$libsuff
        addcflags=-I$OPT_GNUTLS/include
        version="" # we just don't know
        gtlslib=$OPT_GNUTLS/lib$libsuff
      fi
    fi

    if test -z "$version"; then
      dnl lots of efforts, still no go
      version="unknown"
    fi

    if test -n "$addlib"; then

      CLEANLIBS="$LIBS"
      CLEANCPPFLAGS="$CPPFLAGS"
      CLEANLDFLAGS="$LDFLAGS"

      LIBS="$addlib $LIBS"
      LDFLAGS="$LDFLAGS $addld"
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

        if test -n "$gtlslib"; then
          dnl when shared libs were found in a path that the run-time
          dnl linker doesn't search through, we need to add it to
          dnl LD_LIBRARY_PATH to prevent further configure tests to fail
          dnl due to this
          if test "x$cross_compiling" != "xyes"; then 
            LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$gtlslib"
            export LD_LIBRARY_PATH
            AC_MSG_NOTICE([Added $gtlslib to LD_LIBRARY_PATH])
          fi
        fi
      fi

    fi

  fi dnl GNUTLS not disabled

fi

dnl ---
dnl Check which crypto backend GnuTLS uses
dnl ---

if test "$GNUTLS_ENABLED" = "1"; then
  USE_GNUTLS_NETTLE=
  # First check if we can detect either crypto library via transitive linking
  AC_CHECK_LIB(gnutls, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_CHECK_LIB(gnutls, gcry_control, [ USE_GNUTLS_NETTLE=0 ])
  fi
  # If not, try linking directly to both of them to see if they are available
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_CHECK_LIB(nettle, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])
  fi
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_CHECK_LIB(gcrypt, gcry_control, [ USE_GNUTLS_NETTLE=0 ])
  fi
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_MSG_ERROR([GnuTLS found, but neither gcrypt nor nettle found])
  fi
  if test "$USE_GNUTLS_NETTLE" = "1"; then
    AC_DEFINE(USE_GNUTLS_NETTLE, 1, [if GnuTLS uses nettle as crypto backend])
    AC_SUBST(USE_GNUTLS_NETTLE, [1])
    LIBS="-lnettle $LIBS"
  else
    LIBS="-lgcrypt $LIBS"
  fi
fi

dnl ---
dnl We require GnuTLS with SRP support.
dnl ---
if test "$GNUTLS_ENABLED" = "1"; then
  AC_CHECK_LIB(gnutls, gnutls_srp_verifier,
   [
     AC_DEFINE(HAVE_GNUTLS_SRP, 1, [if you have the function gnutls_srp_verifier])
     AC_SUBST(HAVE_GNUTLS_SRP, [1])
   ])
fi

dnl ----------------------------------------------------
dnl check for PolarSSL
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for PolarSSL files & libraries.
OPT_POLARSSL=no

_cppflags=$CPPFLAGS
_ldflags=$LDFLAGS
AC_ARG_WITH(polarssl,dnl
AC_HELP_STRING([--with-polarssl=PATH],[where to look for PolarSSL, PATH points to the installation root])
AC_HELP_STRING([--without-polarssl], [disable PolarSSL detection]),
  OPT_POLARSSL=$withval)

if test "$curl_ssl_msg" = "$init_ssl_msg"; then

  if test X"$OPT_POLARSSL" != Xno; then

    if test "$OPT_POLARSSL" = "yes"; then
      OPT_POLARSSL=""
    fi

    if test -z "$OPT_POLARSSL" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(polarssl, havege_init,
      dnl libpolarssl found, set the variable
       [
         AC_DEFINE(USE_POLARSSL, 1, [if PolarSSL is enabled])
         AC_SUBST(USE_POLARSSL, [1])
         POLARSSL_ENABLED=1
         USE_POLARSSL="yes"
         curl_ssl_msg="enabled (PolarSSL)"
        ])
    fi

    addld=""
    addlib=""
    addcflags=""
    polarssllib=""

    if test "x$USE_POLARSSL" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_POLARSSL/lib$libsuff
      addcflags=-I$OPT_POLARSSL/include
      polarssllib=$OPT_POLARSSL/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(polarssl, ssl_init,
       [
       AC_DEFINE(USE_POLARSSL, 1, [if PolarSSL is enabled])
       AC_SUBST(USE_POLARSSL, [1])
       POLARSSL_ENABLED=1
       USE_POLARSSL="yes"
       curl_ssl_msg="enabled (PolarSSL)"
       ],
       [
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
       ])
    fi

    if test "x$USE_POLARSSL" = "xyes"; then
      AC_MSG_NOTICE([detected PolarSSL])

      LIBS="-lpolarssl $LIBS"

      if test -n "$polarssllib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$polarssllib"
          export LD_LIBRARY_PATH
          AC_MSG_NOTICE([Added $polarssllib to LD_LIBRARY_PATH])
        fi
      fi
    fi

  fi dnl PolarSSL not disabled

fi

dnl ----------------------------------------------------
dnl check for CyaSSL
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for CyaSSL files & libraries.
OPT_CYASSL=no

_cppflags=$CPPFLAGS
_ldflags=$LDFLAGS
AC_ARG_WITH(cyassl,dnl
AC_HELP_STRING([--with-cyassl=PATH],[where to look for CyaSSL, PATH points to the installation root (default: system lib default)])
AC_HELP_STRING([--without-cyassl], [disable CyaSSL detection]),
  OPT_CYASSL=$withval)

if test "$curl_ssl_msg" = "$init_ssl_msg"; then

  if test X"$OPT_CYASSL" != Xno; then

    if test "$OPT_CYASSL" = "yes"; then
      OPT_CYASSL=""
    fi

    if test -z "$OPT_CYASSL" ; then
      dnl check for lib in system default first

      AC_CHECK_LIB(cyassl, CyaSSL_Init,
      dnl libcyassl found, set the variable
       [
         AC_DEFINE(USE_CYASSL, 1, [if CyaSSL is enabled])
         AC_SUBST(USE_CYASSL, [1])
         CYASSL_ENABLED=1
         USE_CYASSL="yes"
         curl_ssl_msg="enabled (CyaSSL)"
        ])
    fi

    addld=""
    addlib=""
    addcflags=""
    cyassllib=""

    if test "x$USE_CYASSL" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_CYASSL/lib$libsuff
      addcflags=-I$OPT_CYASSL/include
      cyassllib=$OPT_CYASSL/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(cyassl, CyaSSL_Init,
       [
       AC_DEFINE(USE_CYASSL, 1, [if CyaSSL is enabled])
       AC_SUBST(USE_CYASSL, [1])
       CYASSL_ENABLED=1
       USE_CYASSL="yes"
       curl_ssl_msg="enabled (CyaSSL)"
       ],
       [
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
       ])
    fi

    if test "x$USE_CYASSL" = "xyes"; then
      AC_MSG_NOTICE([detected CyaSSL])

      LIBS="-lcyassl -lm $LIBS"

      if test -n "$cyassllib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$cyassllib"
          export LD_LIBRARY_PATH
          AC_MSG_NOTICE([Added $cyassllib to LD_LIBRARY_PATH])
        fi
      fi

    fi

  fi dnl CyaSSL not disabled

fi

dnl ----------------------------------------------------
dnl NSS. Only check if GnuTLS and OpenSSL are not enabled
dnl ----------------------------------------------------

dnl Default to compiler & linker defaults for NSS files & libraries.
OPT_NSS=no

AC_ARG_WITH(nss,dnl
AC_HELP_STRING([--with-nss=PATH],[where to look for NSS, PATH points to the installation root])
AC_HELP_STRING([--without-nss], [disable NSS detection]),
  OPT_NSS=$withval)

if test "$curl_ssl_msg" = "$init_ssl_msg"; then

  if test X"$OPT_NSS" != Xno; then

    addld=""
    addlib=""
    addcflags=""
    nssprefix=""
    version=""

    if test "x$OPT_NSS" = "xyes"; then

      CURL_CHECK_PKGCONFIG(nss)

      if test "$PKGCONFIG" != "no" ; then
        addlib=`$PKGCONFIG --libs nss`
        addcflags=`$PKGCONFIG --cflags nss`
        version=`$PKGCONFIG --modversion nss`
        nssprefix=`$PKGCONFIG --variable=prefix nss`
      else
        dnl Without pkg-config, we check for nss-config

        check=`nss-config --version 2>/dev/null`
        if test -n "$check"; then
          addlib=`nss-config --libs`
          addcflags=`nss-config --cflags`
          version=`nss-config --version`
          nssprefix=`nss-config --prefix`
        else
          addlib="-lnss3"
          addcflags=""
          version="unknown"
        fi
      fi
    else
        # Without pkg-config, we'll kludge in some defaults
        addlib="-L$OPT_NSS/lib -lssl3 -lsmime3 -lnss3 -lplds4 -lplc4 -lnspr4 -lpthread -ldl"
        addcflags="-I$OPT_NSS/include"
        version="unknown"
        nssprefix=$OPT_NSS
    fi

    if test -n "$addlib"; then

      CLEANLIBS="$LIBS"
      CLEANCPPFLAGS="$CPPFLAGS"

      LIBS="$addlib $LIBS"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      dnl The function PK11_CreateGenericObject is needed to load libnsspem.so
      AC_CHECK_LIB(nss3, PK11_CreateGenericObject,
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

        dnl NSS_InitContext() was introduced in NSS 3.12.5 and helps to prevent
        dnl collisions on NSS initialization/shutdown with other libraries
        AC_CHECK_FUNC(NSS_InitContext,
        [
          AC_DEFINE(HAVE_NSS_INITCONTEXT, 1, [if you have the NSS_InitContext function])
          AC_SUBST(HAVE_NSS_INITCONTEXT, [1])
        ])

        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$nssprefix/lib$libsuff"
          export LD_LIBRARY_PATH
          AC_MSG_NOTICE([Added $nssprefix/lib$libsuff to LD_LIBRARY_PATH])
        fi
      fi

    fi

  fi dnl NSS not disabled

fi dnl curl_ssl_msg = init_ssl_msg

OPT_AXTLS=off

AC_ARG_WITH(axtls,dnl
AC_HELP_STRING([--with-axtls=PATH],[Where to look for axTLS, PATH points to the axTLS installation prefix (default: /usr/local).  Ignored if another SSL engine is selected.])
AC_HELP_STRING([--without-axtls], [disable axTLS]),
  OPT_AXTLS=$withval)

if test "$curl_ssl_msg" = "$init_ssl_msg"; then
  if test X"$OPT_AXTLS" != Xno; then
    dnl backup the pre-axtls variables
    CLEANLDFLAGS="$LDFLAGS"
    CLEANCPPFLAGS="$CPPFLAGS"
    CLEANLIBS="$LIBS"

    case "$OPT_AXTLS" in
    yes)
      dnl --with-axtls (without path) used
      PREFIX_AXTLS=/usr/local
      LIB_AXTLS="$PREFIX_AXTLS/lib"
      LDFLAGS="$LDFLAGS -L$LIB_AXTLS"
      CPPFLAGS="$CPPFLAGS -I$PREFIX_AXTLS/include"
      ;;
    off)
      dnl no --with-axtls option given, just check default places
      PREFIX_AXTLS=
      ;;
    *)
      dnl check the given --with-axtls spot
      PREFIX_AXTLS=$OPT_AXTLS
      LIB_AXTLS="$PREFIX_AXTLS/lib"
      LDFLAGS="$LDFLAGS -L$LIB_AXTLS"
      CPPFLAGS="$CPPFLAGS -I$PREFIX_AXTLS/include"
      ;;
    esac

    AC_CHECK_LIB(axtls, ssl_version,[
      LIBS="-laxtls $LIBS"
      AC_DEFINE(USE_AXTLS, 1, [if axTLS is enabled])
      AC_SUBST(USE_AXTLS, [1])
      AXTLS_ENABLED=1
      USE_AXTLS="yes"
      curl_ssl_msg="enabled (axTLS)"


      LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$LIB_AXTLS"
      export LD_LIBRARY_PATH
      AC_MSG_NOTICE([Added $LIB_AXTLS to LD_LIBRARY_PATH])
      ],[
      LDFLAGS="$CLEANLDFLAGS"
      CPPFLAGS="$CLEANCPPFLAGS"
      LIBS="$CLEANLIBS"
    ])
  fi
fi

if test "x$OPENSSL_ENABLED$GNUTLS_ENABLED$NSS_ENABLED$POLARSSL_ENABLED$AXTLS_ENABLED$CYASSL_ENABLED$WINSSL_ENABLED$DARWINSSL_ENABLED" = "x"; then
  AC_MSG_WARN([SSL disabled, you will not be able to use HTTPS, FTPS, NTLM and more.])
  AC_MSG_WARN([Use --with-ssl, --with-gnutls, --with-polarssl, --with-cyassl, --with-nss, --with-axtls, --with-winssl, or --with-darwinssl to address this.])
else
  # SSL is enabled, genericly
  AC_SUBST(SSL_ENABLED)
  SSL_ENABLED="1"
fi

dnl **********************************************************************
dnl Check for the CA bundle
dnl **********************************************************************

CURL_CHECK_CA_BUNDLE

dnl **********************************************************************
dnl Check for libmetalink
dnl **********************************************************************

OPT_LIBMETALINK=no

AC_ARG_WITH(libmetalink,dnl
AC_HELP_STRING([--with-libmetalink=PATH],[where to look for libmetalink, PATH points to the installation root])
AC_HELP_STRING([--without-libmetalink], [disable libmetalink detection]),
  OPT_LIBMETALINK=$withval)

if test X"$OPT_LIBMETALINK" != Xno; then

  addld=""
  addlib=""
  addcflags=""
  version=""
  libmetalinklib=""

  PKGTEST="no"
  if test "x$OPT_LIBMETALINK" = "xyes"; then
    dnl this is with no partiular path given
    PKGTEST="yes"
    CURL_CHECK_PKGCONFIG(libmetalink)
  else
    dnl When particular path is given, set PKG_CONFIG_LIBDIR using the path.
    LIBMETALINK_PCDIR="$OPT_LIBMETALINK/lib/pkgconfig"
    AC_MSG_NOTICE([PKG_CONFIG_LIBDIR will be set to "$LIBMETALINK_PCDIR"])
    if test -f "$LIBMETALINK_PCDIR/libmetalink.pc"; then
      PKGTEST="yes"
    fi
    if test "$PKGTEST" = "yes"; then
      CURL_CHECK_PKGCONFIG(libmetalink, [$LIBMETALINK_PCDIR])
    fi
  fi
  if test "$PKGTEST" = "yes" && test "$PKGCONFIG" != "no"; then
    addlib=`CURL_EXPORT_PCDIR([$LIBMETALINK_PCDIR]) dnl
      $PKGCONFIG --libs-only-l libmetalink`
    addld=`CURL_EXPORT_PCDIR([$LIBMETALINK_PCDIR]) dnl
      $PKGCONFIG --libs-only-L libmetalink`
    addcflags=`CURL_EXPORT_PCDIR([$LIBMETALINK_PCDIR]) dnl
      $PKGCONFIG --cflags-only-I libmetalink`
    version=`CURL_EXPORT_PCDIR([$LIBMETALINK_PCDIR]) dnl
      $PKGCONFIG --modversion libmetalink`
    libmetalinklib=`echo $addld | $SED -e 's/-L//'`
  fi
  if test -n "$addlib"; then

    clean_CPPFLAGS="$CPPFLAGS"
    clean_LDFLAGS="$LDFLAGS"
    clean_LIBS="$LIBS"
    CPPFLAGS="$addcflags $clean_CPPFLAGS"
    LDFLAGS="$addld $clean_LDFLAGS"
    LIBS="$addlib $clean_LIBS"
    AC_MSG_CHECKING([if libmetalink is recent enough])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
#       include <metalink/metalink.h>
      ]],[[
        if(0 != metalink_strerror(0)) /* added in 0.1.0 */
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes ($version)])
      want_metalink="yes"
    ],[
      AC_MSG_RESULT([no ($version)])
      AC_MSG_NOTICE([libmetalink library defective or too old])
      want_metalink="no"
    ])
    CPPFLAGS="$clean_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS"
    LIBS="$clean_LIBS"
    if test "$want_metalink" = "yes"; then
      dnl finally libmetalink will be used
      AC_DEFINE(USE_METALINK, 1, [Define to enable metalink support])
      LIBMETALINK_LIBS=$addlib
      LIBMETALINK_LDFLAGS=$addld
      LIBMETALINK_CPPFLAGS=$addcflags
      AC_SUBST([LIBMETALINK_LIBS])
      AC_SUBST([LIBMETALINK_LDFLAGS])
      AC_SUBST([LIBMETALINK_CPPFLAGS])
      curl_mtlnk_msg="enabled"
    fi

  fi
fi

dnl **********************************************************************
dnl Check for the presence of LIBSSH2 libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for LIBSSH2 files & libraries.
OPT_LIBSSH2=off
AC_ARG_WITH(libssh2,dnl
AC_HELP_STRING([--with-libssh2=PATH],[Where to look for libssh2, PATH points to the LIBSSH2 installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
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
    CURL_CHECK_PKGCONFIG(libssh2)

    if test "$PKGCONFIG" != "no" ; then
      LIB_SSH2=`$PKGCONFIG --libs-only-l libssh2`
      LD_SSH2=`$PKGCONFIG --libs-only-L libssh2`
      CPP_SSH2=`$PKGCONFIG --cflags-only-I libssh2`
      version=`$PKGCONFIG --modversion libssh2`
      DIR_SSH2=`echo $LD_SSH2 | $SED -e 's/-L//'`
    fi

    ;;
  off)
    dnl no --with-libssh2 option given, just check default places
    ;;
  *)
    dnl use the given --with-libssh2 spot
    PREFIX_SSH2=$OPT_LIBSSH2
    ;;
  esac

  dnl if given with a prefix, we set -L and -I based on that
  if test -n "$PREFIX_SSH2"; then
    LIB_SSH2="-lssh2"
    LD_SSH2=-L${PREFIX_SSH2}/lib$libsuff
    CPP_SSH2=-I${PREFIX_SSH2}/include
    DIR_SSH2=${PREFIX_SSH2}/lib$libsuff
  fi

  LDFLAGS="$LDFLAGS $LD_SSH2"
  CPPFLAGS="$CPPFLAGS $CPP_SSH2"
  LIBS="$LIB_SSH2 $LIBS"

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
    if test -n "$DIR_SSH2"; then
       dnl when the libssh2 shared libs were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to LD_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       dnl libssh2_version is a post 1.0 addition
       dnl libssh2_init and libssh2_exit were added in 1.2.5
       dnl libssh2_scp_send64 was added in 1.2.6
       dnl libssh2_session_handshake was added in 1.2.8
       AC_CHECK_FUNCS( libssh2_version libssh2_init libssh2_exit \
                       libssh2_scp_send64 libssh2_session_handshake)
       if test "x$cross_compiling" != "xyes"; then
         LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$DIR_SSH2"
         export LD_LIBRARY_PATH
         AC_MSG_NOTICE([Added $DIR_SSH2 to LD_LIBRARY_PATH])
       fi
    fi
  else
    dnl no libssh2, revert back to clean variables
    LDFLAGS=$CLEANLDFLAGS
    CPPFLAGS=$CLEANCPPFLAGS
    LIBS=$CLEANLIBS
  fi
fi

dnl **********************************************************************
dnl Check for the presence of LIBRTMP libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for LIBRTMP files & libraries.
OPT_LIBRTMP=off
AC_ARG_WITH(librtmp,dnl
AC_HELP_STRING([--with-librtmp=PATH],[Where to look for librtmp, PATH points to the LIBRTMP installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AC_HELP_STRING([--without-librtmp], [disable LIBRTMP]),
  OPT_LIBRTMP=$withval)

if test X"$OPT_LIBRTMP" != Xno; then
  dnl backup the pre-librtmp variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_LIBRTMP" in
  yes)
    dnl --with-librtmp (without path) used
    CURL_CHECK_PKGCONFIG(librtmp)

    if test "$PKGCONFIG" != "no" ; then
      LIB_RTMP=`$PKGCONFIG --libs-only-l librtmp`
      LD_RTMP=`$PKGCONFIG --libs-only-L librtmp`
      CPP_RTMP=`$PKGCONFIG --cflags-only-I librtmp`
      version=`$PKGCONFIG --modversion librtmp`
      DIR_RTMP=`echo $LD_RTMP | $SED -e 's/-L//'`
    else
      dnl To avoid link errors, we do not allow --librtmp without
      dnl a pkgconfig file
      AC_MSG_ERROR([--librtmp was specified but could not find librtmp pkgconfig file.])
    fi

    ;;
  off)
    dnl no --with-librtmp option given, just check default places
    LIB_RTMP="-lrtmp"
    ;;
  *)
    dnl use the given --with-librtmp spot
    PREFIX_RTMP=$OPT_LIBRTMP
    ;;
  esac

  dnl if given with a prefix, we set -L and -I based on that
  if test -n "$PREFIX_RTMP"; then
    LD_RTMP=-L${PREFIX_RTMP}/lib$libsuff
    CPP_RTMP=-I${PREFIX_RTMP}/include
    DIR_RTMP=${PREFIX_RTMP}/lib$libsuff
  fi

  LDFLAGS="$LDFLAGS $LD_RTMP"
  CPPFLAGS="$CPPFLAGS $CPP_RTMP"
  LIBS="$LIB_RTMP $LIBS"

  AC_CHECK_LIB(rtmp, RTMP_Init,
    [
     AC_CHECK_HEADERS(librtmp/rtmp.h,
        curl_rtmp_msg="enabled (librtmp)"
        LIBRTMP_ENABLED=1
        AC_DEFINE(USE_LIBRTMP, 1, [if librtmp is in use])
        AC_SUBST(USE_LIBRTMP, [1])
     )
    ],
      dnl not found, revert back to clean variables
      LDFLAGS=$CLEANLDFLAGS
      CPPFLAGS=$CLEANCPPFLAGS
      LIBS=$CLEANLIBS
  )

  if test X"$OPT_LIBRTMP" != Xoff &&
     test "$LIBRTMP_ENABLED" != "1"; then
    AC_MSG_ERROR([librtmp libs and/or directories were not found where specified!])
  fi

fi

dnl **********************************************************************
dnl Check for linker switch for versioned symbols
dnl **********************************************************************

versioned_symbols_flavour=
AC_MSG_CHECKING([whether versioned symbols are wanted])
AC_ARG_ENABLE(versioned-symbols,
AC_HELP_STRING([--enable-versioned-symbols], [Enable versioned symbols in shared library])
AC_HELP_STRING([--disable-versioned-symbols], [Disable versioned symbols in shared library]),
[ case "$enableval" in
  yes) AC_MSG_RESULT(yes)
    AC_MSG_CHECKING([if libraries can be versioned])
    GLD=`$LD --help < /dev/null 2>/dev/null | grep version-script`
    if test -z "$GLD"; then
        AC_MSG_RESULT(no)
        AC_MSG_WARN([You need an ld version supporting the --version-script option])
    else
        AC_MSG_RESULT(yes)
        if test "x$OPENSSL_ENABLED" = "x1"; then
          versioned_symbols_flavour="OPENSSL_"
        elif test "x$GNUTLS_ENABLED" == "x1"; then
          versioned_symbols_flavour="GNUTLS_"
        elif test "x$NSS_ENABLED" == "x1"; then
          versioned_symbols_flavour="NSS_"
        elif test "x$POLARSSL_ENABLED" == "x1"; then
          versioned_symbols_flavour="POLARSSL_"
        elif test "x$CYASSL_ENABLED" == "x1"; then
          versioned_symbols_flavour="CYASSL_"
        elif test "x$AXTLS_ENABLED" == "x1"; then
          versioned_symbols_flavour="AXTLS_"
        elif test "x$WINSSL_ENABLED" == "x1"; then
          versioned_symbols_flavour="WINSSL_"
        elif test "x$DARWINSSL_ENABLED" == "x1"; then
          versioned_symbols_flavour="DARWINSSL_"
        else
          versioned_symbols_flavour=""
        fi
        versioned_symbols="yes"
    fi
    ;;

  *)   AC_MSG_RESULT(no)
    ;;
  esac
], [
AC_MSG_RESULT(no)
]
)

AC_SUBST([CURL_LT_SHLIB_VERSIONED_FLAVOUR],
  ["$versioned_symbols_flavour"])
AM_CONDITIONAL([CURL_LT_SHLIB_USE_VERSIONED_SYMBOLS],
  [test "x$versioned_symbols" = 'xyes'])

dnl -------------------------------------------------
dnl check winidn option before other IDN libraries
dnl -------------------------------------------------

AC_MSG_CHECKING([whether to enable Windows native IDN (Windows native builds only)])
OPT_WINIDN="default"
AC_ARG_WITH(winidn,
AC_HELP_STRING([--with-winidn=PATH],[enable Windows native IDN])
AC_HELP_STRING([--without-winidn], [disable Windows native IDN]),
  OPT_WINIDN=$withval)
case "$OPT_WINIDN" in
  no|default)
    dnl --without-winidn option used or configure option not specified
    want_winidn="no"
    AC_MSG_RESULT([no])
    ;;
  yes)
    dnl --with-winidn option used without path
    want_winidn="yes"
    want_winidn_path="default"
    AC_MSG_RESULT([yes])
    ;;
  *)
    dnl --with-winidn option used with path
    want_winidn="yes"
    want_winidn_path="$withval"
    AC_MSG_RESULT([yes ($withval)])
    ;;
esac

if test "$want_winidn" = "yes"; then
  dnl winidn library support has been requested
  clean_CPPFLAGS="$CPPFLAGS"
  clean_LDFLAGS="$LDFLAGS"
  clean_LIBS="$LIBS"
  WINIDN_LIBS="-lnormaliz"
  #
  if test "$want_winidn_path" != "default"; then
    dnl path has been specified
    dnl pkg-config not available or provides no info
    WINIDN_LDFLAGS="-L$want_winidn_path/lib$libsuff"
    WINIDN_CPPFLAGS="-I$want_winidn_path/include"
    WINIDN_DIR="$want_winidn_path/lib$libsuff"
  fi
  #
  CPPFLAGS="$WINIDN_CPPFLAGS $CPPFLAGS"
  LDFLAGS="$WINIDN_LDFLAGS $LDFLAGS"
  LIBS="$WINIDN_LIBS $LIBS"
  #
  AC_MSG_CHECKING([if IdnToUnicode can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([IdnToUnicode])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_winidn="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_winidn="no"
  ])
  #
  if test "$tst_links_winidn" = "yes"; then
    AC_DEFINE(USE_WIN32_IDN, 1, [Define to 1 if you have the `normaliz' (WinIDN) library (-lnormaliz).])
    AC_DEFINE(WANT_IDN_PROTOTYPES, 1, [Define to 1 to provide own prototypes.])
    AC_SUBST([IDN_ENABLED], [1])
    curl_idn_msg="enabled (Windows-native)"
  else
    AC_MSG_WARN([Cannot find libraries for IDN support: IDN disabled])
    CPPFLAGS="$clean_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS"
    LIBS="$clean_LIBS"
  fi
fi

dnl **********************************************************************
dnl Check for the presence of IDN libraries and headers
dnl **********************************************************************

AC_MSG_CHECKING([whether to build with libidn])
OPT_IDN="default"
AC_ARG_WITH(libidn,
AC_HELP_STRING([--with-libidn=PATH],[Enable libidn usage])
AC_HELP_STRING([--without-libidn],[Disable libidn usage]),
  [OPT_IDN=$withval])
case "$OPT_IDN" in
  no)
    dnl --without-libidn option used
    want_idn="no"
    AC_MSG_RESULT([no])
    ;;
  default)
    dnl configure option not specified
    want_idn="yes"
    want_idn_path="default"
    AC_MSG_RESULT([(assumed) yes])
    ;;
  yes)
    dnl --with-libidn option used without path
    want_idn="yes"
    want_idn_path="default"
    AC_MSG_RESULT([yes])
    ;;
  *)
    dnl --with-libidn option used with path
    want_idn="yes"
    want_idn_path="$withval"
    AC_MSG_RESULT([yes ($withval)])
    ;;
esac

if test "$want_idn" = "yes"; then
  dnl idn library support has been requested
  clean_CPPFLAGS="$CPPFLAGS"
  clean_LDFLAGS="$LDFLAGS"
  clean_LIBS="$LIBS"
  PKGCONFIG="no"
  #
  if test "$want_idn_path" != "default"; then
    dnl path has been specified
    IDN_PCDIR="$want_idn_path/lib$libsuff/pkgconfig"
    CURL_CHECK_PKGCONFIG(libidn, [$IDN_PCDIR])
    if test "$PKGCONFIG" != "no"; then
      IDN_LIBS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --libs-only-l libidn 2>/dev/null`
      IDN_LDFLAGS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --libs-only-L libidn 2>/dev/null`
      IDN_CPPFLAGS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --cflags-only-I libidn 2>/dev/null`
      IDN_DIR=`echo $IDN_LDFLAGS | $SED -e 's/-L//'`
    else
      dnl pkg-config not available or provides no info
      IDN_LIBS="-lidn"
      IDN_LDFLAGS="-L$want_idn_path/lib$libsuff"
      IDN_CPPFLAGS="-I$want_idn_path/include"
      IDN_DIR="$want_idn_path/lib$libsuff"
    fi
  else
    dnl path not specified
    CURL_CHECK_PKGCONFIG(libidn)
    if test "$PKGCONFIG" != "no"; then
      IDN_LIBS=`$PKGCONFIG --libs-only-l libidn 2>/dev/null`
      IDN_LDFLAGS=`$PKGCONFIG --libs-only-L libidn 2>/dev/null`
      IDN_CPPFLAGS=`$PKGCONFIG --cflags-only-I libidn 2>/dev/null`
      IDN_DIR=`echo $IDN_LDFLAGS | $SED -e 's/-L//'`
    else
      dnl pkg-config not available or provides no info
      IDN_LIBS="-lidn"
    fi
  fi
  #
  if test "$PKGCONFIG" != "no"; then
    AC_MSG_NOTICE([pkg-config: IDN_LIBS: "$IDN_LIBS"])
    AC_MSG_NOTICE([pkg-config: IDN_LDFLAGS: "$IDN_LDFLAGS"])
    AC_MSG_NOTICE([pkg-config: IDN_CPPFLAGS: "$IDN_CPPFLAGS"])
    AC_MSG_NOTICE([pkg-config: IDN_DIR: "$IDN_DIR"])
  else
    AC_MSG_NOTICE([IDN_LIBS: "$IDN_LIBS"])
    AC_MSG_NOTICE([IDN_LDFLAGS: "$IDN_LDFLAGS"])
    AC_MSG_NOTICE([IDN_CPPFLAGS: "$IDN_CPPFLAGS"])
    AC_MSG_NOTICE([IDN_DIR: "$IDN_DIR"])
  fi
  #
  CPPFLAGS="$IDN_CPPFLAGS $CPPFLAGS"
  LDFLAGS="$IDN_LDFLAGS $LDFLAGS"
  LIBS="$IDN_LIBS $LIBS"
  #
  AC_MSG_CHECKING([if idna_to_ascii_4i can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([idna_to_ascii_4i])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_libidn="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_libidn="no"
  ])
  if test "$tst_links_libidn" = "no"; then
    AC_MSG_CHECKING([if idna_to_ascii_lz can be linked])
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([idna_to_ascii_lz])
    ],[
      AC_MSG_RESULT([yes])
      tst_links_libidn="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_links_libidn="no"
    ])
  fi
  #
  if test "$tst_links_libidn" = "yes"; then
    AC_DEFINE(HAVE_LIBIDN, 1, [Define to 1 if you have the `idn' library (-lidn).])
    dnl different versions of libidn have different setups of these:
    AC_CHECK_FUNCS( idn_free idna_strerror tld_strerror )
    AC_CHECK_HEADERS( idn-free.h tld.h )
    if test "x$ac_cv_header_tld_h" = "xyes"; then
      AC_SUBST([IDN_ENABLED], [1])
      curl_idn_msg="enabled"
      if test -n "$IDN_DIR"; then
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$IDN_DIR"
        export LD_LIBRARY_PATH
        AC_MSG_NOTICE([Added $IDN_DIR to LD_LIBRARY_PATH])
      fi
    else
      AC_MSG_WARN([Libraries for IDN support too old: IDN disabled])
      CPPFLAGS="$clean_CPPFLAGS"
      LDFLAGS="$clean_LDFLAGS"
      LIBS="$clean_LIBS"
    fi
  else
    AC_MSG_WARN([Cannot find libraries for IDN support: IDN disabled])
    CPPFLAGS="$clean_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS"
    LIBS="$clean_LIBS"
  fi
fi


dnl Let's hope this split URL remains working:
dnl http://publibn.boulder.ibm.com/doc_link/en_US/a_doc_lib/aixprggd/ \
dnl genprogc/thread_quick_ref.htm


dnl **********************************************************************
dnl Back to "normal" configuring
dnl **********************************************************************

dnl Checks for header files.
AC_HEADER_STDC

CURL_CHECK_HEADER_MALLOC
CURL_CHECK_HEADER_MEMORY

dnl Now check for the very most basic headers. Then we can use these
dnl ones as default-headers when checking for the rest!
AC_CHECK_HEADERS(
        sys/types.h \
        sys/time.h \
        sys/select.h \
        sys/socket.h \
        sys/ioctl.h \
        sys/uio.h \
        assert.h \
        unistd.h \
        stdlib.h \
        limits.h \
        arpa/inet.h \
        net/if.h \
        netinet/in.h \
        sys/un.h \
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
        socket.h \
        sys/resource.h \
        libgen.h \
        locale.h \
        errno.h \
        stdbool.h \
        arpa/tftp.h \
        sys/filio.h \
        sys/wait.h \
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
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
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

AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(short)
CURL_CONFIGURE_LONG
AC_CHECK_SIZEOF(time_t)
AC_CHECK_SIZEOF(off_t)

soname_bump=no
if test x"$ac_cv_native_windows" != "xyes" &&
   test $ac_cv_sizeof_off_t -ne $curl_sizeof_curl_off_t; then
  AC_MSG_WARN([This libcurl built is probably not ABI compatible with previous])
  AC_MSG_WARN([builds! You MUST read lib/README.curl_off_t to figure it out.])
  soname_bump=yes
fi


AC_CHECK_TYPE(long long,
   [AC_DEFINE(HAVE_LONGLONG, 1,
      [Define to 1 if the compiler supports the 'long long' data type.])]
   longlong="yes"
)

if test "xyes" = "x$longlong"; then
  AC_MSG_CHECKING([if numberLL works])
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      long long val = 1000LL;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_LL, 1, [if your compiler supports LL])
  ],[
    AC_MSG_RESULT([no])
  ])
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

CURL_CONFIGURE_CURL_SOCKLEN_T

CURL_CONFIGURE_PULL_SYS_POLL

TYPE_IN_ADDR_T

TYPE_SOCKADDR_STORAGE

TYPE_SIG_ATOMIC_T

AC_TYPE_SIGNAL

CURL_CHECK_FUNC_SELECT

CURL_CHECK_FUNC_RECV
CURL_CHECK_FUNC_SEND
CURL_CHECK_MSG_NOSIGNAL

CURL_CHECK_FUNC_ALARM
CURL_CHECK_FUNC_BASENAME
CURL_CHECK_FUNC_CLOSESOCKET
CURL_CHECK_FUNC_CLOSESOCKET_CAMEL
CURL_CHECK_FUNC_CONNECT
CURL_CHECK_FUNC_FCNTL
CURL_CHECK_FUNC_FDOPEN
CURL_CHECK_FUNC_FREEADDRINFO
CURL_CHECK_FUNC_FREEIFADDRS
CURL_CHECK_FUNC_FSETXATTR
CURL_CHECK_FUNC_FTRUNCATE
CURL_CHECK_FUNC_GETADDRINFO
CURL_CHECK_FUNC_GAI_STRERROR
CURL_CHECK_FUNC_GETHOSTBYADDR
CURL_CHECK_FUNC_GETHOSTBYADDR_R
CURL_CHECK_FUNC_GETHOSTBYNAME
CURL_CHECK_FUNC_GETHOSTBYNAME_R
CURL_CHECK_FUNC_GETHOSTNAME
CURL_CHECK_FUNC_GETIFADDRS
CURL_CHECK_FUNC_GETSERVBYPORT_R
CURL_CHECK_FUNC_GMTIME_R
CURL_CHECK_FUNC_INET_NTOA_R
CURL_CHECK_FUNC_INET_NTOP
CURL_CHECK_FUNC_INET_PTON
CURL_CHECK_FUNC_IOCTL
CURL_CHECK_FUNC_IOCTLSOCKET
CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL
CURL_CHECK_FUNC_LOCALTIME_R
CURL_CHECK_FUNC_MEMRCHR
CURL_CHECK_FUNC_POLL
CURL_CHECK_FUNC_SETSOCKOPT
CURL_CHECK_FUNC_SIGACTION
CURL_CHECK_FUNC_SIGINTERRUPT
CURL_CHECK_FUNC_SIGNAL
CURL_CHECK_FUNC_SIGSETJMP
CURL_CHECK_FUNC_SOCKET
CURL_CHECK_FUNC_SOCKETPAIR
CURL_CHECK_FUNC_STRCASECMP
CURL_CHECK_FUNC_STRCMPI
CURL_CHECK_FUNC_STRDUP
CURL_CHECK_FUNC_STRERROR_R
CURL_CHECK_FUNC_STRICMP
CURL_CHECK_FUNC_STRNCASECMP
CURL_CHECK_FUNC_STRNCMPI
CURL_CHECK_FUNC_STRNICMP
CURL_CHECK_FUNC_STRSTR
CURL_CHECK_FUNC_STRTOK_R
CURL_CHECK_FUNC_STRTOLL
CURL_CHECK_FUNC_WRITEV

case $host in
  *msdosdjgpp)
     ac_cv_func_pipe=no
     skipcheck_pipe=yes
     AC_MSG_NOTICE([skip check for pipe on msdosdjgpp])
    ;;
esac

AC_CHECK_FUNCS([fork \
  geteuid \
  getpass_r \
  getppid \
  getprotobyname \
  getpwuid \
  getrlimit \
  gettimeofday \
  inet_addr \
  perror \
  pipe \
  setlocale \
  setmode \
  setrlimit \
  uname \
  utime
],[
],[
  func="$ac_func"
  eval skipcheck=\$skipcheck_$func
  if test "x$skipcheck" != "xyes"; then
    AC_MSG_CHECKING([deeper for $func])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        $func ();
      ]])
    ],[
      AC_MSG_RESULT([yes])
      eval "ac_cv_func_$func=yes"
      AC_DEFINE_UNQUOTED(XC_SH_TR_CPP([HAVE_$func]), [1],
        [Define to 1 if you have the $func function.])
    ],[
      AC_MSG_RESULT([but still no])
    ])
  fi
])

dnl Check if the getnameinfo function is available
dnl and get the types of five of its arguments.
CURL_CHECK_FUNC_GETNAMEINFO

if test "$ipv6" = "yes"; then
  if test "$ac_cv_func_getaddrinfo" = "yes"; then
    AC_DEFINE(ENABLE_IPV6, 1, [Define if you want to enable IPv6 support])
    IPV6_ENABLED=1
    AC_SUBST(IPV6_ENABLED)
  fi
  CURL_CHECK_NI_WITHSCOPEID
fi

CURL_CHECK_NONBLOCKING_SOCKET

dnl ************************************************************
dnl nroff tool stuff
dnl

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

CURL_CHECK_LIB_ARES
AM_CONDITIONAL(USE_EMBEDDED_ARES, test x$embedded_ares = xyes)

if test "x$ac_cv_native_windows" != "xyes" &&
   test "x$enable_shared" = "xyes"; then
  build_libhostname=yes
else
  build_libhostname=no
fi
AM_CONDITIONAL(BUILD_LIBHOSTNAME, test x$build_libhostname = xyes)

CURL_CHECK_OPTION_THREADED_RESOLVER

if test "x$want_thres" = xyes && test "x$want_ares" = xyes; then
  AC_MSG_ERROR(
[Options --enable-threaded-resolver and --enable-ares are mutually exclusive])
fi

if test "$want_thres" = "yes"; then
  AC_CHECK_HEADER(pthread.h,
    [ AC_DEFINE(HAVE_PTHREAD_H, 1, [if you have <pthread.h>])
      save_CFLAGS="$CFLAGS"

      dnl first check for function without lib
      AC_CHECK_FUNC(pthread_create, [USE_THREADS_POSIX=1] )

      dnl if it wasn't found without lib, search for it in pthread lib
      if test "$USE_THREADS_POSIX" != "1"
      then
        CFLAGS="$CFLAGS -pthread"
        AC_CHECK_LIB(pthread, pthread_create,
                     [USE_THREADS_POSIX=1],
                     [ CFLAGS="$save_CFLAGS"])
      fi

      if test "x$USE_THREADS_POSIX" = "x1"
      then
        AC_DEFINE(USE_THREADS_POSIX, 1, [if you want POSIX threaded DNS lookup])
        curl_res_msg="POSIX threaded"
      fi


  ])
fi

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
         curl_sspi_msg="enabled"
       else
         AC_MSG_RESULT(no)
         AC_MSG_WARN([--enable-sspi Ignored. Only supported on native Windows builds.])
       fi
       ;;
  *)
       if test "x$WINSSL_ENABLED" = "x1"; then
         # --with-winssl implies --enable-sspi
         AC_MSG_RESULT(yes)
       else
         AC_MSG_RESULT(no)
       fi
       ;;
  esac ],
       if test "x$WINSSL_ENABLED" = "x1"; then
         # --with-winssl implies --enable-sspi
         AC_MSG_RESULT(yes)
       else
         AC_MSG_RESULT(no)
       fi
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

CURL_CHECK_OPTION_NTLM_WB

CURL_CHECK_NTLM_WB

dnl ************************************************************
dnl disable TLS-SRP authentication
dnl
AC_MSG_CHECKING([whether to enable TLS-SRP authentication])
AC_ARG_ENABLE(tls-srp,
AC_HELP_STRING([--enable-tls-srp],[Enable TLS-SRP authentication])
AC_HELP_STRING([--disable-tls-srp],[Disable TLS-SRP authentication]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_TLS_SRP, 1, [to disable TLS-SRP authentication])
       want_tls_srp=no
       ;;
  *)   AC_MSG_RESULT(yes)
       want_tls_srp=yes
       ;;
  esac ],
       AC_MSG_RESULT(yes)
       want_tls_srp=yes
)

if test "$want_tls_srp" = "yes" && ( test "x$HAVE_GNUTLS_SRP" = "x1" || test "x$HAVE_SSLEAY_SRP" = "x1") ; then
   AC_DEFINE(USE_TLS_SRP, 1, [Use TLS-SRP authentication])
   USE_TLS_SRP=1
   curl_tls_srp_msg="enabled"
fi

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
dnl hiding of library internal symbols
dnl
CURL_CONFIGURE_SYMBOL_HIDING

dnl ************************************************************
dnl enforce SONAME bump
dnl

AC_MSG_CHECKING([whether to enforce SONAME bump])
AC_ARG_ENABLE(soname-bump,
AC_HELP_STRING([--enable-soname-bump],[Enable enforced SONAME bump])
AC_HELP_STRING([--disable-soname-bump],[Disable enforced SONAME bump]),
[ case "$enableval" in
  yes)   AC_MSG_RESULT(yes)
         soname_bump=yes
         ;;
  *)
         AC_MSG_RESULT(no)
         ;;
  esac ],
        AC_MSG_RESULT($soname_bump)
)
AM_CONDITIONAL(SONAME_BUMP, test x$soname_bump = xyes)

dnl
dnl All the library dependencies put into $LIB apply to libcurl only.
dnl
LIBCURL_LIBS=$LIBS

AC_SUBST(LIBCURL_LIBS)
AC_SUBST(CURL_NETWORK_LIBS)
AC_SUBST(CURL_NETWORK_AND_TIME_LIBS)

dnl BLANK_AT_MAKETIME may be used in our Makefile.am files to blank
dnl LIBS variable used in generated makefile at makefile processing
dnl time. Doing this functionally prevents LIBS from being used for
dnl all link targets in given makefile.
BLANK_AT_MAKETIME=
AC_SUBST(BLANK_AT_MAKETIME)

AM_CONDITIONAL(CROSSCOMPILING, test x$cross_compiling = xyes)

dnl yes or no
ENABLE_SHARED="$enable_shared"
AC_SUBST(ENABLE_SHARED)

dnl to let curl-config output the static libraries correctly
ENABLE_STATIC="$enable_static"
AC_SUBST(ENABLE_STATIC)


dnl
dnl For keeping supported features and protocols also in pkg-config file
dnl since it is more cross-compile friendly than curl-config
dnl

if test "x$USE_SSLEAY" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSL"
elif test -n "$SSL_ENABLED"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSL"
fi
if test "@KRB4_ENABLED@" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES KRB4"
fi
if test "x$IPV6_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES IPv6"
fi
if test "x$HAVE_LIBZ" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES libz"
fi
if test "x$USE_ARES" = "x1" -o "x$USE_THREADS_POSIX" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES AsynchDNS"
fi
if test "x$IDN_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES IDN"
fi
if test "x$USE_WINDOWS_SSPI" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSPI"
fi
if test "x$CURL_DISABLE_HTTP" != "x1"; then
  if test "x$USE_SSLEAY" = "x1" -o "x$USE_WINDOWS_SSPI" = "x1" \
      -o "x$GNUTLS_ENABLED" = "x1" -o "x$NSS_ENABLED" = "x1" \
      -o "x$DARWINSSL_ENABLED" = "x1"; then
    SUPPORT_FEATURES="$SUPPORT_FEATURES NTLM"
    if test "x$NTLM_WB_ENABLED" = "x1"; then
      SUPPORT_FEATURES="$SUPPORT_FEATURES NTLM_WB"
    fi
  fi
fi
if test "x$USE_TLS_SRP" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES TLS-SRP"
fi

AC_SUBST(SUPPORT_FEATURES)

dnl For supported protocols in pkg-config file
if test "x$CURL_DISABLE_HTTP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS HTTP"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS HTTPS"
  fi
fi
if test "x$CURL_DISABLE_FTP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS FTP"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS FTPS"
  fi
fi
if test "x$CURL_DISABLE_FILE" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS FILE"
fi
if test "x$CURL_DISABLE_TELNET" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS TELNET"
fi
if test "x$CURL_DISABLE_LDAP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS LDAP"
  if test "x$CURL_DISABLE_LDAPS" != "x1"; then
    if (test "x$USE_OPENLDAP" = "x1" && test "x$SSL_ENABLED" = "x1") ||
      (test "x$USE_OPENLDAP" != "x1"  && test "x$HAVE_LDAP_SSL" = "x1"); then
      SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS LDAPS"
    fi
  fi
fi
if test "x$CURL_DISABLE_DICT" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS DICT"
fi
if test "x$CURL_DISABLE_TFTP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS TFTP"
fi
if test "x$CURL_DISABLE_GOPHER" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS GOPHER"
fi
if test "x$CURL_DISABLE_POP3" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS POP3"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS POP3S"
  fi
fi
if test "x$CURL_DISABLE_IMAP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS IMAP"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS IMAPS"
  fi
fi
if test "x$CURL_DISABLE_SMTP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SMTP"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SMTPS"
  fi
fi
if test "x$USE_LIBSSH2" = "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SCP"
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SFTP"
fi
if test "x$CURL_DISABLE_RTSP" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS RTSP"
fi
if test "x$USE_LIBRTMP" = "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS RTMP"
fi

dnl replace spaces with newlines
dnl sort the lines
dnl replace the newlines back to spaces
SUPPORT_PROTOCOLS=`echo $SUPPORT_PROTOCOLS | tr ' ' '\012' | sort | tr '\012' ' '`

AC_SUBST(SUPPORT_PROTOCOLS)

dnl squeeze whitespace out of some variables

squeeze CFLAGS
squeeze CPPFLAGS
squeeze DEFS
squeeze LDFLAGS
squeeze LIBS

squeeze LIBCURL_LIBS
squeeze CURL_NETWORK_LIBS
squeeze CURL_NETWORK_AND_TIME_LIBS

squeeze SUPPORT_FEATURES
squeeze SUPPORT_PROTOCOLS

XC_CHECK_BUILD_FLAGS

if test "x$want_curldebug_assumed" = "xyes" &&
  test "x$want_curldebug" = "xyes" && test "x$USE_ARES" = "x1"; then
  ac_configure_args="$ac_configure_args --enable-curldebug"
fi

AC_CONFIG_FILES([Makefile \
           docs/Makefile \
           docs/examples/Makefile \
           docs/libcurl/Makefile \
           include/Makefile \
           include/curl/Makefile \
           src/Makefile \
           lib/Makefile \
           lib/libcurl.vers \
           tests/Makefile \
           tests/certs/Makefile \
           tests/certs/scripts/Makefile \
           tests/data/Makefile \
           tests/server/Makefile \
           tests/libtest/Makefile \
           tests/unit/Makefile \
           packages/Makefile \
           packages/Win32/Makefile \
           packages/Win32/cygwin/Makefile \
           packages/Linux/Makefile \
           packages/Linux/RPM/Makefile \
           packages/Linux/RPM/curl.spec \
           packages/Linux/RPM/curl-ssl.spec \
           packages/Solaris/Makefile \
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

CURL_GENERATE_CONFIGUREHELP_PM

AC_MSG_NOTICE([Configured to build curl/libcurl:

  curl version:     ${CURLVERSION}
  Host setup:       ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  SSL support:      ${curl_ssl_msg}
  SSH support:      ${curl_ssh_msg}
  zlib support:     ${curl_zlib_msg}
  krb4 support:     ${curl_krb4_msg}
  GSSAPI support:   ${curl_gss_msg}
  SPNEGO support:   ${curl_spnego_msg}
  TLS-SRP support:  ${curl_tls_srp_msg}
  resolver:         ${curl_res_msg}
  ipv6 support:     ${curl_ipv6_msg}
  IDN support:      ${curl_idn_msg}
  Build libcurl:    Shared=${enable_shared}, Static=${enable_static}
  Built-in manual:  ${curl_manual_msg}
  --libcurl option: ${curl_libcurl_msg}
  Verbose errors:   ${curl_verbose_msg}
  SSPI support:     ${curl_sspi_msg}
  ca cert bundle:   ${ca}
  ca cert path:     ${capath}
  LDAP support:     ${curl_ldap_msg}
  LDAPS support:    ${curl_ldaps_msg}
  RTSP support:     ${curl_rtsp_msg}
  RTMP support:     ${curl_rtmp_msg}
  metalink support: ${curl_mtlnk_msg}
  Protocols:        ${SUPPORT_PROTOCOLS}
])

if test "x$soname_bump" = "xyes"; then

cat <<EOM
  SONAME bump:     yes - WARNING: this library will be built with the SONAME
                   number bumped due to (a detected) ABI breakage.
                   See lib/README.curl_off_t for details on this.
EOM

fi

