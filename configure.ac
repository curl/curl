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
#***************************************************************************
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

dnl We don't know the version number "statically" so we use a dash here
AC_INIT([curl], [-], [a suitable curl mailing list: https://curl.se/mail/])

XC_OVR_ZZ50
XC_OVR_ZZ60
CURL_OVERRIDE_AUTOCONF

dnl configure script copyright
AC_COPYRIGHT([Copyright (C) Daniel Stenberg, <daniel@haxx.se>
This configure script may be copied, distributed and modified under the
terms of the curl license; see COPYING for more details])

AC_CONFIG_SRCDIR([lib/urldata.h])
AC_CONFIG_HEADERS(lib/curl_config.h)
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

CURL_CHECK_OPTION_DEBUG
CURL_CHECK_OPTION_OPTIMIZE
CURL_CHECK_OPTION_WARNINGS
CURL_CHECK_OPTION_WERROR
CURL_CHECK_OPTION_CURLDEBUG
CURL_CHECK_OPTION_SYMBOL_HIDING
CURL_CHECK_OPTION_ARES
CURL_CHECK_OPTION_RT
CURL_CHECK_OPTION_ECH

XC_CHECK_PATH_SEPARATOR

#
# save the configure arguments
#
CONFIGURE_OPTIONS="\"$ac_configure_args\""
AC_SUBST(CONFIGURE_OPTIONS)

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

dnl 'grep -E' is mandatory for configure process and libtool.
dnl Set it now, allowing it to be changed later.
if test -z "$EGREP"; then
  dnl allow it to be overridden
  AC_MSG_CHECKING([that grep -E works])
  if echo a | ($GREP -E '(a|b)') >/dev/null 2>&1; then
    EGREP="$GREP -E"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_PATH_PROG([EGREP], [egrep], [not_found],
      [$PATH:/usr/bin:/usr/local/bin])
  fi
fi
if test -z "$EGREP" || test "$EGREP" = "not_found"; then
  AC_MSG_ERROR([grep -E is not working and egrep is not found in PATH. Cannot continue.])
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

dnl figure out the libcurl version
CURLVERSION=`$SED -ne 's/^#define LIBCURL_VERSION "\(.*\)".*/\1/p' ${srcdir}/include/curl/curlver.h`
XC_CHECK_PROG_CC
CURL_ATOMIC

dnl for --enable-code-coverage
CURL_COVERAGE

XC_AUTOMAKE
AC_MSG_CHECKING([curl version])
AC_MSG_RESULT($CURLVERSION)

AC_SUBST(CURLVERSION)

dnl
dnl we extract the numerical version for curl-config only
VERSIONNUM=`$SED -ne 's/^#define LIBCURL_VERSION_NUM 0x\([0-9A-Fa-f]*\).*/\1/p' ${srcdir}/include/curl/curlver.h`
AC_SUBST(VERSIONNUM)

dnl Solaris pkgadd support definitions
PKGADD_PKG="HAXXcurl"
PKGADD_NAME="curl - a client that groks URLs"
PKGADD_VENDOR="curl.se"
AC_SUBST(PKGADD_PKG)
AC_SUBST(PKGADD_NAME)
AC_SUBST(PKGADD_VENDOR)

dnl
dnl initialize all the info variables
    curl_ssl_msg="no      (--with-{openssl,gnutls,nss,mbedtls,wolfssl,schannel,secure-transport,amissl,bearssl,rustls} )"
    curl_ssh_msg="no      (--with-{libssh,libssh2})"
   curl_zlib_msg="no      (--with-zlib)"
 curl_brotli_msg="no      (--with-brotli)"
   curl_zstd_msg="no      (--with-zstd)"
    curl_gss_msg="no      (--with-gssapi)"
  curl_gsasl_msg="no      (--with-gsasl)"
curl_tls_srp_msg="no      (--enable-tls-srp)"
    curl_res_msg="default (--enable-ares / --enable-threaded-resolver)"
   curl_ipv6_msg="no      (--enable-ipv6)"
curl_unix_sockets_msg="no      (--enable-unix-sockets)"
    curl_idn_msg="no      (--with-{libidn2,winidn})"
 curl_manual_msg="no      (--enable-manual)"
curl_libcurl_msg="enabled (--disable-libcurl-option)"
curl_verbose_msg="enabled (--disable-verbose)"
   curl_sspi_msg="no      (--enable-sspi)"
   curl_ldap_msg="no      (--enable-ldap / --with-ldap-lib / --with-lber-lib)"
  curl_ldaps_msg="no      (--enable-ldaps)"
   curl_rtsp_msg="no      (--enable-rtsp)"
   curl_rtmp_msg="no      (--with-librtmp)"
    curl_psl_msg="no      (--with-libpsl)"
 curl_altsvc_msg="enabled (--disable-alt-svc)"
curl_headers_msg="enabled (--disable-headers-api)"
   curl_hsts_msg="enabled (--disable-hsts)"
     curl_ws_msg="no      (--enable-websockets)"
    ssl_backends=
     curl_h1_msg="enabled (internal)"
     curl_h2_msg="no      (--with-nghttp2, --with-hyper)"
     curl_h3_msg="no      (--with-ngtcp2 --with-nghttp3, --with-quiche, --with-msh3)"

enable_altsvc="yes"
hsts="yes"

dnl
dnl Save some initial values the user might have provided
dnl
INITIAL_LDFLAGS=$LDFLAGS
INITIAL_LIBS=$LIBS

dnl
dnl Generates a shell script to run the compiler with LD_LIBRARY_PATH set to
dnl the value used right now. This lets CURL_RUN_IFELSE set LD_LIBRARY_PATH to
dnl something different but only have that affect the execution of the results
dnl of the compile, not change the libraries for the compiler itself.
dnl
compilersh="run-compiler"
export "CURL_SAVED_CC=$CC"
export "CURL_SAVED_LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
cat <<\EOF > "$compilersh"
export "CC=$CURL_SAVED_CC"
export "LD_LIBRARY_PATH=$CURL_SAVED_LD_LIBRARY_PATH"
exec $CC "$@"
EOF

dnl **********************************************************************
dnl See which TLS backend(s) that are requested. Just do all the
dnl TLS AC_ARG_WITH() invokes here and do the checks later
dnl **********************************************************************
OPT_SCHANNEL=no
AC_ARG_WITH(schannel,dnl
AS_HELP_STRING([--with-schannel],[enable Windows native SSL/TLS]),
  OPT_SCHANNEL=$withval
  TLSCHOICE="schannel")

OPT_SECURETRANSPORT=no
AC_ARG_WITH(secure-transport,dnl
AS_HELP_STRING([--with-secure-transport],[enable Apple OS native SSL/TLS]),[
  OPT_SECURETRANSPORT=$withval
  TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }Secure-Transport"
])

OPT_AMISSL=no
AC_ARG_WITH(amissl,dnl
AS_HELP_STRING([--with-amissl],[enable Amiga native SSL/TLS (AmiSSL)]),[
  OPT_AMISSL=$withval
  TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }AmiSSL"
])

OPT_OPENSSL=no
dnl Default to no CA bundle
ca="no"
AC_ARG_WITH(ssl,dnl
AS_HELP_STRING([--with-ssl=PATH],[old version of --with-openssl])
AS_HELP_STRING([--without-ssl], [build without any TLS library]),[
  OPT_SSL=$withval
  OPT_OPENSSL=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }OpenSSL"
  else
    SSL_DISABLED="D"
  fi
])

AC_ARG_WITH(openssl,dnl
AS_HELP_STRING([--with-openssl=PATH],[Where to look for OpenSSL, PATH points to the SSL installation (default: /usr/local/ssl); when possible, set the PKG_CONFIG_PATH environment variable instead of using this option]),[
  OPT_OPENSSL=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }OpenSSL"
  fi
])

OPT_GNUTLS=no
AC_ARG_WITH(gnutls,dnl
AS_HELP_STRING([--with-gnutls=PATH],[where to look for GnuTLS, PATH points to the installation root]),[
  OPT_GNUTLS=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }GnuTLS"
  fi
])

OPT_MBEDTLS=no
AC_ARG_WITH(mbedtls,dnl
AS_HELP_STRING([--with-mbedtls=PATH],[where to look for mbedTLS, PATH points to the installation root]),[
  OPT_MBEDTLS=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }mbedTLS"
  fi
])

OPT_WOLFSSL=no
AC_ARG_WITH(wolfssl,dnl
AS_HELP_STRING([--with-wolfssl=PATH],[where to look for WolfSSL, PATH points to the installation root (default: system lib default)]),[
  OPT_WOLFSSL=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }wolfSSL"
  fi
])

OPT_BEARSSL=no
AC_ARG_WITH(bearssl,dnl
AS_HELP_STRING([--with-bearssl=PATH],[where to look for BearSSL, PATH points to the installation root]),[
  OPT_BEARSSL=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }BearSSL"
  fi
])

OPT_RUSTLS=no
AC_ARG_WITH(rustls,dnl
AS_HELP_STRING([--with-rustls=PATH],[where to look for rustls, PATH points to the installation root]),[
  OPT_RUSTLS=$withval
  if test X"$withval" != Xno; then
    TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }rustls"
    experimental="$experimental rustls"
  fi
])

OPT_NSS_AWARE=no
AC_ARG_WITH(nss-deprecated,dnl
AS_HELP_STRING([--with-nss-deprecated],[confirm you realize NSS is going away]),
  if test X"$withval" != Xno; then
    OPT_NSS_AWARE=$withval
  fi
)

OPT_NSS=no
AC_ARG_WITH(nss,dnl
AS_HELP_STRING([--with-nss=PATH],[where to look for NSS, PATH points to the installation root]),
  OPT_NSS=$withval
  if test X"$withval" != Xno; then

    if test X"$OPT_NSS_AWARE" = "Xno" ; then
      AC_MSG_ERROR([NSS use must be confirmed using --with-nss-deprecated. NSS support will be dropped from curl in August 2022. See docs/DEPRECATE.md])
    fi

    [TLSCHOICE="${TLSCHOICE:+$TLSCHOICE, }NSS"]
  fi
)

TEST_NGHTTPX=nghttpx
AC_ARG_WITH(test-nghttpx,dnl
AS_HELP_STRING([--with-test-nghttpx=PATH],[where to find nghttpx for testing]),
  TEST_NGHTTPX=$withval
  if test X"$OPT_TEST_NGHTTPX" = "Xno" ; then
      TEST_NGHTTPX=""
  fi
)
AC_SUBST(TEST_NGHTTPX)

CADDY=caddy
AC_ARG_WITH(test-caddy,dnl
AS_HELP_STRING([--with-test-caddy=PATH],[where to find caddy for testing]),
  CADDY=$withval
  if test X"$OPT_CADDY" = "Xno" ; then
      CADDY=""
  fi
)
AC_SUBST(CADDY)

dnl we'd like a httpd+apachectl as test server
dnl
HTTPD_ENABLED="maybe"
AC_ARG_WITH(test-httpd, [AS_HELP_STRING([--with-test-httpd=PATH],
                         [where to find httpd/apache2 for testing])],
  [request_httpd=$withval], [request_httpd=check])
if test x"$request_httpd" = "xcheck" -o x"$request_httpd" = "xyes"; then
  if test -x "/usr/sbin/apache2" -a -x "/usr/sbin/apache2ctl"; then
    # common location on distros (debian/ubuntu)
    HTTPD="/usr/sbin/apache2"
    APACHECTL="/usr/sbin/apache2ctl"
    AC_PATH_PROG([APXS], [apxs])
    if test "x$APXS" = "x"; then
      AC_MSG_NOTICE([apache2-dev not installed, httpd tests disabled])
      HTTPD_ENABLED="no"
    fi
  else
    AC_PATH_PROG([HTTPD], [httpd])
    if test "x$HTTPD" = "x"; then
      AC_PATH_PROG([HTTPD], [apache2])
    fi
    AC_PATH_PROG([APACHECTL], [apachectl])
    AC_PATH_PROG([APXS], [apxs])
    if test "x$HTTPD" = "x" -o "x$APACHECTL" = "x"; then
      AC_MSG_NOTICE([httpd/apache2 not in PATH, http tests disabled])
      HTTPD_ENABLED="no"
    fi
    if test "x$APXS" = "x"; then
      AC_MSG_NOTICE([apxs not in PATH, http tests disabled])
      HTTPD_ENABLED="no"
    fi
  fi
elif test x"$request_httpd" != "xno"; then
  HTTPD="${request_httpd}/bin/httpd"
  APACHECTL="${request_httpd}/bin/apachectl"
  APXS="${request_httpd}/bin/apxs"
  if test ! -x "${HTTPD}"; then
    AC_MSG_NOTICE([httpd not found as ${HTTPD}, http tests disabled])
    HTTPD_ENABLED="no"
  elif test ! -x "${APACHECTL}"; then
    AC_MSG_NOTICE([apachectl not found as ${APACHECTL}, http tests disabled])
    HTTPD_ENABLED="no"
  elif test ! -x "${APXS}"; then
    AC_MSG_NOTICE([apxs not found as ${APXS}, http tests disabled])
    HTTPD_ENABLED="no"
  else
    AC_MSG_NOTICE([using HTTPD=$HTTPD for tests])
  fi
fi
if test x"$HTTPD_ENABLED" = "xno"; then
  HTTPD=""
  APACHECTL=""
  APXS=""
fi
AC_SUBST(HTTPD)
AC_SUBST(APACHECTL)
AC_SUBST(APXS)

dnl the nghttpx we might use in httpd testing
if test "x$TEST_NGHTTPX" != "x" -a "x$TEST_NGHTTPX" != "xnghttpx"; then
  HTTPD_NGHTTPX="$TEST_NGHTTPX"
else
  AC_PATH_PROG([HTTPD_NGHTTPX], [nghttpx], [],
    [$PATH:/usr/bin:/usr/local/bin])
fi
AC_SUBST(HTTPD_NGHTTPX)

dnl the Caddy server we might use in testing
if test "x$TEST_CADDY" != "x"; then
  CADDY="$TEST_CADDY"
else
  AC_PATH_PROG([CADDY], [caddy])
fi
AC_SUBST(CADDY)

dnl If no TLS choice has been made, check if it was explicitly disabled or
dnl error out to force the user to decide.
if test -z "$TLSCHOICE"; then
  if test "x$OPT_SSL" != "xno"; then
    AC_MSG_ERROR([select TLS backend(s) or disable TLS with --without-ssl.

Select from these:

  --with-amissl
  --with-bearssl
  --with-gnutls
  --with-mbedtls
  --with-nss
  --with-openssl (also works for BoringSSL and libressl)
  --with-rustls
  --with-schannel
  --with-secure-transport
  --with-wolfssl
])
  fi
fi

AC_ARG_WITH(darwinssl,,
  AC_MSG_ERROR([--with-darwin-ssl no longer works!]))

dnl
dnl Detect the canonical host and target build environment
dnl

AC_CANONICAL_HOST
dnl Get system canonical name
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

# Silence warning: ar: 'u' modifier ignored since 'D' is the default
AC_SUBST(AR_FLAGS, [cr])

dnl This defines _ALL_SOURCE for AIX
CURL_CHECK_AIX_ALL_SOURCE

dnl Our configure and build reentrant settings
CURL_CONFIGURE_THREAD_SAFE
CURL_CONFIGURE_REENTRANT

dnl check for how to do large files
AC_SYS_LARGEFILE

XC_LIBTOOL

LT_LANG([Windows Resource])

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

CURL_CFLAG_EXTRAS=""
if test X"$want_werror" = Xyes; then
  CURL_CFLAG_EXTRAS="-Werror"
  if test "$compiler_id" = "GNU_C"; then
    dnl enable -pedantic-errors for GCC 5 and later,
    dnl as before that it was the same as -Werror=pedantic
    if test "$compiler_num" -ge "500"; then
      CURL_CFLAG_EXTRAS="$CURL_CFLAG_EXTRAS -pedantic-errors"
    fi
  fi
fi
AC_SUBST(CURL_CFLAG_EXTRAS)

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

# For original MinGW (ie not MinGW-w64) define the Windows minimum supported OS
# version to Windows XP (0x501) if it hasn't already been defined by the user.
# Without this override original MinGW defaults the version to Windows NT 4.0.
# Note original MinGW sets _WIN32_WINNT if not defined to whatever WINVER is.
case $host in
  *-*-mingw32*)
    AC_MSG_CHECKING([if MinGW minimum supported OS should be set to XP])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <_mingw.h>
      ]],[[
#if defined(__MINGW64_VERSION_MAJOR) || \
    defined(WINVER) || \
    defined(_WIN32_WINNT)
#error
#endif
      ]])
    ],[
      CPPFLAGS="$CPPFLAGS -DWINVER=0x501"
      AC_MSG_RESULT([yes])
    ],[
      AC_MSG_RESULT([no])
    ])
    ;;
esac

# Detect original MinGW (not MinGW-w64)
curl_mingw_original=no
case $host in
  *-*-mingw32*)
    AC_MSG_CHECKING([using original MinGW (not MinGW-w64)])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#include <_mingw.h>
      ]],[[
#if defined(__MINGW64_VERSION_MAJOR)
#error
#endif
      ]])
    ],[
      curl_mingw_original=yes
      curl_mingw_die=yes
      AC_MSG_RESULT([yes])
    ],[
      AC_MSG_RESULT([no])
    ])
    ;;
esac


AC_ARG_WITH(mingw1-deprecated,dnl
AS_HELP_STRING([--with-mingw1-deprecated],[confirm you realize support for mingw v1 is dying]),
  if test X"$withval" != Xno; then
    curl_mingw_die=
  fi
)

if test -n "$curl_mingw_die"; then
  AC_MSG_ERROR([support for mingw v1 is going away, enable temporarily with --with-mingw1-deprecated])
fi

dnl **********************************************************************
dnl Compilation based checks should not be done before this point.
dnl **********************************************************************

dnl **********************************************************************
dnl Make sure that our checks for headers windows.h winsock2.h
dnl and ws2tcpip.h take precedence over any other further checks which
dnl could be done later using AC_CHECK_HEADER or AC_CHECK_HEADERS for
dnl this specific header files. And do them before its results are used.
dnl **********************************************************************

CURL_CHECK_HEADER_WINDOWS
CURL_CHECK_NATIVE_WINDOWS
case X-"$curl_cv_native_windows" in
  X-yes)
    CURL_CHECK_HEADER_WINSOCK2
    CURL_CHECK_HEADER_WS2TCPIP
    CURL_CHECK_HEADER_WINCRYPT
    CURL_CHECK_HEADER_WINLDAP
    ;;
  *)
    curl_cv_header_winsock2_h="no"
    curl_cv_header_ws2tcpip_h="no"
    curl_cv_header_wincrypt_h="no"
    curl_cv_header_winldap_h="no"
    ;;
esac
CURL_CHECK_WIN32_LARGEFILE
CURL_CHECK_WIN32_CRYPTO

CURL_DARWIN_CFLAGS
CURL_DARWIN_SYSTEMCONFIGURATION
CURL_SUPPORTS_BUILTIN_AVAILABLE

AM_CONDITIONAL([HAVE_WINDRES],
  [test "$curl_cv_native_windows" = "yes" && test -n "${RC}"])

if test "$curl_cv_native_windows" = "yes"; then
  AM_COND_IF([HAVE_WINDRES],,
    [AC_MSG_ERROR([windres not found in PATH. Windows builds require windres. Cannot continue.])])
fi

dnl ************************************************************
dnl switch off particular protocols
dnl
AC_MSG_CHECKING([whether to support http])
AC_ARG_ENABLE(http,
AS_HELP_STRING([--enable-http],[Enable HTTP support])
AS_HELP_STRING([--disable-http],[Disable HTTP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_HTTP, 1, [to disable HTTP])
       disable_http="yes"
       AC_MSG_WARN([disable HTTP disables FTP over proxy and RTSP])
       AC_SUBST(CURL_DISABLE_HTTP, [1])
       AC_DEFINE(CURL_DISABLE_RTSP, 1, [to disable RTSP])
       AC_SUBST(CURL_DISABLE_RTSP, [1])
       dnl toggle off alt-svc too when HTTP is disabled
       AC_DEFINE(CURL_DISABLE_ALTSVC, 1, [disable alt-svc])
       AC_DEFINE(CURL_DISABLE_HSTS, 1, [disable HSTS])
       curl_h1_msg="no      (--enable-http, --with-hyper)"
       curl_altsvc_msg="no";
       curl_hsts_msg="no      (--enable-hsts)";
       enable_altsvc="no"
       hsts="no"
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)
AC_MSG_CHECKING([whether to support ftp])
AC_ARG_ENABLE(ftp,
AS_HELP_STRING([--enable-ftp],[Enable FTP support])
AS_HELP_STRING([--disable-ftp],[Disable FTP support]),
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
AS_HELP_STRING([--enable-file],[Enable FILE support])
AS_HELP_STRING([--disable-file],[Disable FILE support]),
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
AS_HELP_STRING([--enable-ldap],[Enable LDAP support])
AS_HELP_STRING([--disable-ldap],[Disable LDAP support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_LDAP, 1, [to disable LDAP])
       AC_SUBST(CURL_DISABLE_LDAP, [1])
       ;;
  yes)
       ldap_askedfor="yes"
       AC_MSG_RESULT(yes)
       ;;
  *)
       AC_MSG_RESULT(yes)
       ;;
  esac ],[
       AC_MSG_RESULT(yes) ]
)
AC_MSG_CHECKING([whether to support ldaps])
AC_ARG_ENABLE(ldaps,
AS_HELP_STRING([--enable-ldaps],[Enable LDAPS support])
AS_HELP_STRING([--disable-ldaps],[Disable LDAPS support]),
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

dnl **********************************************************************
dnl Check for Hyper
dnl **********************************************************************

OPT_HYPER="no"

AC_ARG_WITH(hyper,
AS_HELP_STRING([--with-hyper=PATH],[Enable hyper usage])
AS_HELP_STRING([--without-hyper],[Disable hyper usage]),
  [OPT_HYPER=$withval])
case "$OPT_HYPER" in
  no)
    dnl --without-hyper option used
    want_hyper="no"
    ;;
  yes)
    dnl --with-hyper option used without path
    want_hyper="default"
    want_hyper_path=""
    ;;
  *)
    dnl --with-hyper option used with path
    want_hyper="yes"
    want_hyper_path="$withval"
    ;;
esac

if test X"$want_hyper" != Xno; then
  if test "x$disable_http" = "xyes"; then
    AC_MSG_ERROR([--with-hyper is not compatible with --disable-http])
  fi

  dnl backup the pre-hyper variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(hyper, $want_hyper_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_HYPER=`CURL_EXPORT_PCDIR([$want_hyper_path])
      $PKGCONFIG --libs-only-l hyper`
    CPP_HYPER=`CURL_EXPORT_PCDIR([$want_hyper_path]) dnl
      $PKGCONFIG --cflags-only-I hyper`
    LD_HYPER=`CURL_EXPORT_PCDIR([$want_hyper_path])
      $PKGCONFIG --libs-only-L hyper`
  else
    dnl no hyper pkg-config found
    LIB_HYPER="-lhyper -ldl -lpthread -lm"
    if test X"$want_hyper" != Xdefault; then
      CPP_HYPER=-I"$want_hyper_path/capi/include"
      LD_HYPER="-L$want_hyper_path/target/release -L$want_hyper_path/target/debug"
    fi
  fi
  if test -n "$LIB_HYPER"; then
    AC_MSG_NOTICE([-l is $LIB_HYPER])
    AC_MSG_NOTICE([-I is $CPP_HYPER])
    AC_MSG_NOTICE([-L is $LD_HYPER])

    LDFLAGS="$LDFLAGS $LD_HYPER"
    CPPFLAGS="$CPPFLAGS $CPP_HYPER"
    LIBS="$LIB_HYPER $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      dnl remove -L, separate with colon if more than one
      DIR_HYPER=`echo $LD_HYPER | $SED -e 's/^-L//' -e 's/ -L/:/g'`
    fi

    AC_CHECK_LIB(hyper, hyper_io_new,
      [
       AC_CHECK_HEADERS(hyper.h,
          experimental="$experimental Hyper"
          AC_MSG_NOTICE([Hyper support is experimental])
          curl_h1_msg="enabled (Hyper)"
          curl_h2_msg=$curl_h1_msg
          HYPER_ENABLED=1
          AC_DEFINE(USE_HYPER, 1, [if hyper is in use])
          AC_SUBST(USE_HYPER, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_HYPER"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_HYPER to CURL_LIBRARY_PATH]),
       )
      ],
      for d in `echo $DIR_HYPER | $SED -e 's/:/ /'`; do
        if test -f "$d/libhyper.a"; then
          AC_MSG_ERROR([hyper was found in $d but was probably built with wrong flags. See docs/HYPER.md.])
        fi
      done
      AC_MSG_ERROR([--with-hyper but hyper was not found. See docs/HYPER.md.])
    )
  fi
fi

if test X"$want_hyper" != Xno; then
  AC_MSG_NOTICE([Disable RTSP support with hyper])
  AC_DEFINE(CURL_DISABLE_RTSP, 1, [to disable RTSP])
  AC_SUBST(CURL_DISABLE_RTSP, [1])
else
  AC_MSG_CHECKING([whether to support rtsp])
  AC_ARG_ENABLE(rtsp,
AS_HELP_STRING([--enable-rtsp],[Enable RTSP support])
AS_HELP_STRING([--disable-rtsp],[Disable RTSP support]),
  [ case "$enableval" in
    no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_RTSP, 1, [to disable RTSP])
       AC_SUBST(CURL_DISABLE_RTSP, [1])
       ;;
    *)
       if test x$CURL_DISABLE_HTTP = x1 ; then
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
fi

AC_MSG_CHECKING([whether to support proxies])
AC_ARG_ENABLE(proxy,
AS_HELP_STRING([--enable-proxy],[Enable proxy support])
AS_HELP_STRING([--disable-proxy],[Disable proxy support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_PROXY, 1, [to disable proxies])
       AC_SUBST(CURL_DISABLE_PROXY, [1])
       https_proxy="no"
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

AC_MSG_CHECKING([whether to support dict])
AC_ARG_ENABLE(dict,
AS_HELP_STRING([--enable-dict],[Enable DICT support])
AS_HELP_STRING([--disable-dict],[Disable DICT support]),
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
AS_HELP_STRING([--enable-telnet],[Enable TELNET support])
AS_HELP_STRING([--disable-telnet],[Disable TELNET support]),
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
AS_HELP_STRING([--enable-tftp],[Enable TFTP support])
AS_HELP_STRING([--disable-tftp],[Disable TFTP support]),
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
AS_HELP_STRING([--enable-pop3],[Enable POP3 support])
AS_HELP_STRING([--disable-pop3],[Disable POP3 support]),
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
AS_HELP_STRING([--enable-imap],[Enable IMAP support])
AS_HELP_STRING([--disable-imap],[Disable IMAP support]),
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


AC_MSG_CHECKING([whether to support smb])
AC_ARG_ENABLE(smb,
AS_HELP_STRING([--enable-smb],[Enable SMB/CIFS support])
AS_HELP_STRING([--disable-smb],[Disable SMB/CIFS support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_SMB, 1, [to disable SMB/CIFS])
       AC_SUBST(CURL_DISABLE_SMB, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

AC_MSG_CHECKING([whether to support smtp])
AC_ARG_ENABLE(smtp,
AS_HELP_STRING([--enable-smtp],[Enable SMTP support])
AS_HELP_STRING([--disable-smtp],[Disable SMTP support]),
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
AS_HELP_STRING([--enable-gopher],[Enable Gopher support])
AS_HELP_STRING([--disable-gopher],[Disable Gopher support]),
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

AC_MSG_CHECKING([whether to support mqtt])
AC_ARG_ENABLE(mqtt,
AS_HELP_STRING([--enable-mqtt],[Enable MQTT support])
AS_HELP_STRING([--disable-mqtt],[Disable MQTT support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_MQTT, 1, [to disable MQTT])
       AC_SUBST(CURL_DISABLE_MQTT, [1])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(no)
)

dnl **********************************************************************
dnl Check for built-in manual
dnl **********************************************************************

AC_MSG_CHECKING([whether to provide built-in manual])
AC_ARG_ENABLE(manual,
AS_HELP_STRING([--enable-manual],[Enable built-in manual])
AS_HELP_STRING([--disable-manual],[Disable built-in manual]),
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
AS_HELP_STRING([--enable-libcurl-option],[Enable --libcurl C code generation support])
AS_HELP_STRING([--disable-libcurl-option],[Disable --libcurl C code generation support]),
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
AS_HELP_STRING([--enable-libgcc],[use libgcc when linking]),
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
  if test "$curl_cv_header_windows_h" = "yes"; then
    if test "$curl_cv_header_winsock2_h" = "yes"; then
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

if test "$HAVE_GETHOSTBYNAME" != "1" -o "${with_amissl+set}" = set
then
  dnl This is for AmigaOS with bsdsocket.library - needs testing before -lnet
  AC_MSG_CHECKING([for gethostbyname for AmigaOS bsdsocket.library])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
  #define __USE_INLINE__
  #include <proto/bsdsocket.h>
  #ifdef __amigaos4__
  struct SocketIFace *ISocket = NULL;
  #else
  struct Library *SocketBase = NULL;
  #endif
    ]],[[
      gethostbyname("www.dummysite.com");
    ]])
  ],[
    AC_MSG_RESULT([yes])
    HAVE_GETHOSTBYNAME="1"
    HAVE_PROTO_BSDSOCKET_H="1"
    AC_DEFINE(HAVE_PROTO_BSDSOCKET_H, 1, [if Amiga bsdsocket.library is in use])
    AC_SUBST(HAVE_PROTO_BSDSOCKET_H, [1])
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

if test "$HAVE_GETHOSTBYNAME" != "1"; then
  AC_MSG_ERROR([couldn't find libraries for gethostbyname()])
fi

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
AS_HELP_STRING([--with-zlib=PATH],[search for zlib in PATH])
AS_HELP_STRING([--without-zlib],[disable use of zlib]),
               [OPT_ZLIB="$withval"])

if test "$OPT_ZLIB" = "no" ; then
    AC_MSG_WARN([zlib disabled])
else
  if test "$OPT_ZLIB" = "yes" ; then
    OPT_ZLIB=""
  fi

  if test -z "$OPT_ZLIB" ; then
    CURL_CHECK_PKGCONFIG(zlib)

    if test "$PKGCONFIG" != "no" ; then
      LIBS="`$PKGCONFIG --libs-only-l zlib` $LIBS"
      LDFLAGS="$LDFLAGS `$PKGCONFIG --libs-only-L zlib`"
      CPPFLAGS="$CPPFLAGS `$PKGCONFIG --cflags-only-I zlib`"
      OPT_ZLIB=""
      HAVE_LIBZ="1"
    fi

    if test -z "$HAVE_LIBZ"; then

      dnl Check for the lib without setting any new path, since many
      dnl people have it in the default path

      AC_CHECK_LIB(z, inflateEnd,
                   dnl libz found, set the variable
                   [HAVE_LIBZ="1"
                    LIBS="-lz $LIBS"],
                   dnl if no lib found, try /usr/local
                   [OPT_ZLIB="/usr/local"])
    fi
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
dnl Check for the presence of BROTLI decoder libraries and headers
dnl **********************************************************************

dnl Brotli project home page: https://github.com/google/brotli

dnl Default to compiler & linker defaults for BROTLI files & libraries.
OPT_BROTLI=off
AC_ARG_WITH(brotli,dnl
AS_HELP_STRING([--with-brotli=PATH],[Where to look for brotli, PATH points to the BROTLI installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--without-brotli], [disable BROTLI]),
  OPT_BROTLI=$withval)

if test X"$OPT_BROTLI" != Xno; then
  dnl backup the pre-brotli variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_BROTLI" in
  yes)
    dnl --with-brotli (without path) used
    CURL_CHECK_PKGCONFIG(libbrotlidec)

    if test "$PKGCONFIG" != "no" ; then
      LIB_BROTLI=`$PKGCONFIG --libs-only-l libbrotlidec`
      LD_BROTLI=`$PKGCONFIG --libs-only-L libbrotlidec`
      CPP_BROTLI=`$PKGCONFIG --cflags-only-I libbrotlidec`
      version=`$PKGCONFIG --modversion libbrotlidec`
      DIR_BROTLI=`echo $LD_BROTLI | $SED -e 's/^-L//'`
    fi

    ;;
  off)
    dnl no --with-brotli option given, just check default places
    ;;
  *)
    dnl use the given --with-brotli spot
    PREFIX_BROTLI=$OPT_BROTLI
    ;;
  esac

  dnl if given with a prefix, we set -L and -I based on that
  if test -n "$PREFIX_BROTLI"; then
    LIB_BROTLI="-lbrotlidec"
    LD_BROTLI=-L${PREFIX_BROTLI}/lib$libsuff
    CPP_BROTLI=-I${PREFIX_BROTLI}/include
    DIR_BROTLI=${PREFIX_BROTLI}/lib$libsuff
  fi

  LDFLAGS="$LDFLAGS $LD_BROTLI"
  CPPFLAGS="$CPPFLAGS $CPP_BROTLI"
  LIBS="$LIB_BROTLI $LIBS"

  AC_CHECK_LIB(brotlidec, BrotliDecoderDecompress)

  AC_CHECK_HEADERS(brotli/decode.h,
    curl_brotli_msg="enabled (libbrotlidec)"
    HAVE_BROTLI=1
    AC_DEFINE(HAVE_BROTLI, 1, [if BROTLI is in use])
    AC_SUBST(HAVE_BROTLI, [1])
  )

  if test X"$OPT_BROTLI" != Xoff &&
     test "$HAVE_BROTLI" != "1"; then
    AC_MSG_ERROR([BROTLI libs and/or directories were not found where specified!])
  fi

  if test "$HAVE_BROTLI" = "1"; then
    if test -n "$DIR_BROTLI"; then
       dnl when the brotli shared libs were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to CURL_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       if test "x$cross_compiling" != "xyes"; then
         CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_BROTLI"
         export CURL_LIBRARY_PATH
         AC_MSG_NOTICE([Added $DIR_BROTLI to CURL_LIBRARY_PATH])
       fi
    fi
  else
    dnl no brotli, revert back to clean variables
    LDFLAGS=$CLEANLDFLAGS
    CPPFLAGS=$CLEANCPPFLAGS
    LIBS=$CLEANLIBS
  fi
fi

dnl **********************************************************************
dnl Check for libzstd
dnl **********************************************************************

dnl Default to compiler & linker defaults for libzstd
OPT_ZSTD=off
AC_ARG_WITH(zstd,dnl
AS_HELP_STRING([--with-zstd=PATH],[Where to look for libzstd, PATH points to the libzstd installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--without-zstd], [disable libzstd]),
  OPT_ZSTD=$withval)

if test X"$OPT_ZSTD" != Xno; then
  dnl backup the pre-zstd variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_ZSTD" in
  yes)
    dnl --with-zstd (without path) used
    CURL_CHECK_PKGCONFIG(libzstd)

    if test "$PKGCONFIG" != "no" ; then
      LIB_ZSTD=`$PKGCONFIG --libs-only-l libzstd`
      LD_ZSTD=`$PKGCONFIG --libs-only-L libzstd`
      CPP_ZSTD=`$PKGCONFIG --cflags-only-I libzstd`
      version=`$PKGCONFIG --modversion libzstd`
      DIR_ZSTD=`echo $LD_ZSTD | $SED -e 's/-L//'`
    fi

    ;;
  off)
    dnl no --with-zstd option given, just check default places
    ;;
  *)
    dnl use the given --with-zstd spot
    PREFIX_ZSTD=$OPT_ZSTD
    ;;
  esac

  dnl if given with a prefix, we set -L and -I based on that
  if test -n "$PREFIX_ZSTD"; then
    LIB_ZSTD="-lzstd"
    LD_ZSTD=-L${PREFIX_ZSTD}/lib$libsuff
    CPP_ZSTD=-I${PREFIX_ZSTD}/include
    DIR_ZSTD=${PREFIX_ZSTD}/lib$libsuff
  fi

  LDFLAGS="$LDFLAGS $LD_ZSTD"
  CPPFLAGS="$CPPFLAGS $CPP_ZSTD"
  LIBS="$LIB_ZSTD $LIBS"

  AC_CHECK_LIB(zstd, ZSTD_createDStream)

  AC_CHECK_HEADERS(zstd.h,
    curl_zstd_msg="enabled (libzstd)"
    HAVE_ZSTD=1
    AC_DEFINE(HAVE_ZSTD, 1, [if libzstd is in use])
    AC_SUBST(HAVE_ZSTD, [1])
  )

  if test X"$OPT_ZSTD" != Xoff &&
     test "$HAVE_ZSTD" != "1"; then
    AC_MSG_ERROR([libzstd was not found where specified!])
  fi

  if test "$HAVE_ZSTD" = "1"; then
    if test -n "$DIR_ZSTD"; then
       dnl when the zstd shared lib were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to
       dnl CURL_LIBRARY_PATH to prevent further configure tests to fail due to
       dnl this

       if test "x$cross_compiling" != "xyes"; then
         CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_ZSTD"
         export CURL_LIBRARY_PATH
         AC_MSG_NOTICE([Added $DIR_ZSTD to CURL_LIBRARY_PATH])
       fi
    fi
  else
    dnl no zstd, revert back to clean variables
    LDFLAGS=$CLEANLDFLAGS
    CPPFLAGS=$CLEANCPPFLAGS
    LIBS=$CLEANLIBS
  fi
fi

dnl **********************************************************************
dnl Check for LDAP
dnl **********************************************************************

LDAPLIBNAME=""
AC_ARG_WITH(ldap-lib,
AS_HELP_STRING([--with-ldap-lib=libname],[Specify name of ldap lib file]),
 [LDAPLIBNAME="$withval"])

LBERLIBNAME=""
AC_ARG_WITH(lber-lib,
AS_HELP_STRING([--with-lber-lib=libname],[Specify name of lber lib file]),
 [LBERLIBNAME="$withval"])

if test x$CURL_DISABLE_LDAP != x1 ; then

  CURL_CHECK_HEADER_LBER
  CURL_CHECK_HEADER_LDAP
  CURL_CHECK_HEADER_LDAP_SSL

  if test -z "$LDAPLIBNAME" ; then
    if test "$curl_cv_native_windows" = "yes"; then
      dnl Windows uses a single and unique LDAP library name
      LDAPLIBNAME="wldap32"
      LBERLIBNAME="no"
    fi
  fi

  if test "$LDAPLIBNAME" ; then
    AC_CHECK_LIB("$LDAPLIBNAME", ldap_init,, [
      if test -n "$ldap_askedfor"; then
        AC_MSG_ERROR([couldn't detect the LDAP libraries])
      fi
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
        if test -n "$ldap_askedfor"; then
          AC_MSG_ERROR([couldn't detect the LDAP libraries])
        fi
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
  AC_CHECK_FUNCS([ldap_url_parse])

  if test "$LDAPLIBNAME" = "wldap32"; then
    curl_ldap_msg="enabled (winldap)"
    AC_DEFINE(USE_WIN32_LDAP, 1, [Use Windows LDAP implementation])
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

AC_MSG_CHECKING([whether to enable IPv6])
AC_ARG_ENABLE(ipv6,
AS_HELP_STRING([--enable-ipv6],[Enable IPv6 (with IPv4) support])
AS_HELP_STRING([--disable-ipv6],[Disable IPv6 support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       ipv6=no
       ;;
  *)   AC_MSG_RESULT(yes)
       ipv6=yes
       ;;
  esac ],

  AC_RUN_IFELSE([AC_LANG_SOURCE([[
/* are AF_INET6 and sockaddr_in6 available? */
#include <sys/types.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#if defined (__TANDEM)
# include <netinet/in6.h>
#endif
#endif
#include <stdlib.h> /* for exit() */
main()
{
 struct sockaddr_in6 s;
 (void)s;
 if (socket(AF_INET6, SOCK_STREAM, 0) < 0)
   exit(1);
 else
   exit(0);
}
]])
],
  AC_MSG_RESULT(yes)
  ipv6=yes,
  AC_MSG_RESULT(no)
  ipv6=no,
  AC_MSG_RESULT(yes)
  ipv6=yes
))

if test "$ipv6" = yes; then
  curl_ipv6_msg="enabled"
  AC_DEFINE(ENABLE_IPV6, 1, [Define if you want to enable IPv6 support])
  IPV6_ENABLED=1
  AC_SUBST(IPV6_ENABLED)

  AC_MSG_CHECKING([if struct sockaddr_in6 has sin6_scope_id member])
  AC_COMPILE_IFELSE([ AC_LANG_PROGRAM([[
#include <sys/types.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#if defined (__TANDEM)
# include <netinet/in6.h>
#endif
#endif
]], [[
  struct sockaddr_in6 s;
  s.sin6_scope_id = 0;
]])], [
  AC_MSG_RESULT([yes])
  AC_DEFINE(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID, 1, [Define to 1 if struct sockaddr_in6 has the sin6_scope_id member])
 ], [
    AC_MSG_RESULT([no])
 ])
fi

dnl **********************************************************************
dnl Check if the operating system allows programs to write to their own argv[]
dnl **********************************************************************

AC_MSG_CHECKING([if argv can be written to])
CURL_RUN_IFELSE([[
int main(int argc, char **argv)
{
#ifdef _WIN32
  /* on Windows, writing to the argv does not hide the argument in
     process lists so it can just be skipped */
  (void)argc;
  (void)argv;
  return 1;
#else
  (void)argc;
  argv[0][0] = ' ';
  return (argv[0][0] == ' ')?0:1;
#endif
}
]],[
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
dnl Check for GSS-API libraries
dnl **********************************************************************

dnl check for GSS-API stuff in the /usr as default

GSSAPI_ROOT="/usr"
AC_ARG_WITH(gssapi-includes,
  AS_HELP_STRING([--with-gssapi-includes=DIR],
                 [Specify location of GSS-API headers]),
  [ GSSAPI_INCS="-I$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi-libs,
  AS_HELP_STRING([--with-gssapi-libs=DIR],
                 [Specify location of GSS-API libs]),
  [ GSSAPI_LIB_DIR="-L$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi,
  AS_HELP_STRING([--with-gssapi=DIR],
                 [Where to look for GSS-API]), [
  GSSAPI_ROOT="$withval"
  if test x"$GSSAPI_ROOT" != xno; then
    want_gss="yes"
    if test x"$GSSAPI_ROOT" = xyes; then
      dnl if yes, then use default root
      GSSAPI_ROOT="/usr"
    fi
  fi
])

: ${KRB5CONFIG:="$GSSAPI_ROOT/bin/krb5-config"}

save_CPPFLAGS="$CPPFLAGS"
AC_MSG_CHECKING([if GSS-API support is requested])
if test x"$want_gss" = xyes; then
  AC_MSG_RESULT(yes)

  if test $GSSAPI_ROOT != "/usr"; then
    CURL_CHECK_PKGCONFIG(mit-krb5-gssapi, $GSSAPI_ROOT/lib/pkgconfig)
  else
    CURL_CHECK_PKGCONFIG(mit-krb5-gssapi)
  fi
  if test -z "$GSSAPI_INCS"; then
     if test -n "$host_alias" -a -f "$GSSAPI_ROOT/bin/$host_alias-krb5-config"; then
        GSSAPI_INCS=`$GSSAPI_ROOT/bin/$host_alias-krb5-config --cflags gssapi`
     elif test "$PKGCONFIG" != "no" ; then
        GSSAPI_INCS=`$PKGCONFIG --cflags mit-krb5-gssapi`
     elif test -f "$KRB5CONFIG"; then
        GSSAPI_INCS=`$KRB5CONFIG --cflags gssapi`
     elif test "$GSSAPI_ROOT" != "yes"; then
        GSSAPI_INCS="-I$GSSAPI_ROOT/include"
     fi
  fi

  CPPFLAGS="$CPPFLAGS $GSSAPI_INCS"

  AC_CHECK_HEADER(gss.h,
    [
      dnl found in the given dirs
      AC_DEFINE(HAVE_GSSGNU, 1, [if you have GNU GSS])
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
              AC_DEFINE(HAVE_GSSHEIMDAL, 1, [if you have Heimdal])
            ],
            [
              dnl no header found, disabling GSS
              want_gss=no
              AC_MSG_WARN(disabling GSS-API support since no header files were found)
            ]
          )
      else
        dnl MIT found
        AC_DEFINE(HAVE_GSSMIT, 1, [if you have MIT Kerberos])
        dnl check if we have a really old MIT Kerberos version (<= 1.2)
        AC_MSG_CHECKING([if GSS-API headers declare GSS_C_NT_HOSTBASED_SERVICE])
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
            [if you have an old MIT Kerberos version, lacking GSS_C_NT_HOSTBASED_SERVICE])
        ])
      fi
    ]
  )
else
  AC_MSG_RESULT(no)
fi
if test x"$want_gss" = xyes; then
  AC_DEFINE(HAVE_GSSAPI, 1, [if you have GSS-API libraries])
  HAVE_GSSAPI=1
  curl_gss_msg="enabled (MIT Kerberos/Heimdal)"

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
        if test $GSSAPI_ROOT != "/usr"; then
          CURL_CHECK_PKGCONFIG(mit-krb5-gssapi, $GSSAPI_ROOT/lib/pkgconfig)
        else
          CURL_CHECK_PKGCONFIG(mit-krb5-gssapi)
        fi
        if test -n "$host_alias" -a -f "$GSSAPI_ROOT/bin/$host_alias-krb5-config"; then
           dnl krb5-config doesn't have --libs-only-L or similar, put everything
           dnl into LIBS
           gss_libs=`$GSSAPI_ROOT/bin/$host_alias-krb5-config --libs gssapi`
           LIBS="$gss_libs $LIBS"
        elif test "$PKGCONFIG" != "no" ; then
           gss_libs=`$PKGCONFIG --libs mit-krb5-gssapi`
           LIBS="$gss_libs $LIBS"
        elif test -f "$KRB5CONFIG"; then
           dnl krb5-config doesn't have --libs-only-L or similar, put everything
           dnl into LIBS
           gss_libs=`$KRB5CONFIG --libs gssapi`
           LIBS="$gss_libs $LIBS"
        else
           case $host in
           *-hp-hpux*)
              gss_libname="gss"
              ;;
           *)
              gss_libname="gssapi"
              ;;
           esac

           if test "$GSSAPI_ROOT" != "yes"; then
              LDFLAGS="$LDFLAGS -L$GSSAPI_ROOT/lib$libsuff"
              LIBS="-l$gss_libname $LIBS"
           else
              LIBS="-l$gss_libname $LIBS"
           fi
        fi
        ;;
     esac
  else
     LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR"
     case $host in
     *-hp-hpux*)
        LIBS="-lgss $LIBS"
        ;;
     *)
        LIBS="-lgssapi $LIBS"
        ;;
     esac
  fi
else
  CPPFLAGS="$save_CPPFLAGS"
fi

if test x"$want_gss" = xyes; then
  AC_MSG_CHECKING([if we can link against GSS-API library])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([gss_init_sec_context])
  ],[
    AC_MSG_RESULT([yes])
  ],[
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([--with-gssapi was specified, but a GSS-API library was not found.])
  ])
fi

build_libstubgss=no
if test x"$want_gss" = "xyes"; then
  build_libstubgss=yes
fi

AM_CONDITIONAL(BUILD_STUB_GSS, test "x$build_libstubgss" = "xyes")

dnl -------------------------------------------------------------
dnl parse --with-default-ssl-backend so it can be validated below
dnl -------------------------------------------------------------

DEFAULT_SSL_BACKEND=no
VALID_DEFAULT_SSL_BACKEND=
AC_ARG_WITH(default-ssl-backend,
AS_HELP_STRING([--with-default-ssl-backend=NAME],[Use NAME as default SSL backend])
AS_HELP_STRING([--without-default-ssl-backend],[Use implicit default SSL backend]),
  [DEFAULT_SSL_BACKEND=$withval])
case "$DEFAULT_SSL_BACKEND" in
  no)
    dnl --without-default-ssl-backend option used
    ;;
  default|yes)
    dnl --with-default-ssl-backend option used without name
    AC_MSG_ERROR([The name of the default SSL backend is required.])
    ;;
  *)
    dnl --with-default-ssl-backend option used with name
    AC_SUBST(DEFAULT_SSL_BACKEND)
    dnl needs to be validated below
    VALID_DEFAULT_SSL_BACKEND=no
    ;;
esac

CURL_WITH_SCHANNEL
CURL_WITH_SECURETRANSPORT
CURL_WITH_AMISSL
CURL_WITH_OPENSSL
CURL_WITH_GNUTLS
CURL_WITH_MBEDTLS
CURL_WITH_WOLFSSL
CURL_WITH_BEARSSL
CURL_WITH_RUSTLS
CURL_WITH_NSS

dnl link required libraries for USE_WIN32_CRYPTO or USE_SCHANNEL
if test "x$USE_WIN32_CRYPTO" = "x1" -o "x$USE_SCHANNEL" = "x1"; then
  LIBS="-ladvapi32 -lcrypt32 $LIBS"
fi

dnl link bcrypt for BCryptGenRandom() (used when building for Vista or newer)
if test "x$curl_cv_native_windows" = "xyes" &&
   test "x$curl_mingw_original" = "xno"; then
  LIBS="-lbcrypt $LIBS"
fi

case "x$SSL_DISABLED$OPENSSL_ENABLED$GNUTLS_ENABLED$NSS_ENABLED$MBEDTLS_ENABLED$WOLFSSL_ENABLED$SCHANNEL_ENABLED$SECURETRANSPORT_ENABLED$BEARSSL_ENABLED$RUSTLS_ENABLED"
in
x)
  AC_MSG_ERROR([TLS not detected, you will not be able to use HTTPS, FTPS, NTLM and more.
Use --with-openssl, --with-gnutls, --with-wolfssl, --with-mbedtls, --with-nss, --with-schannel, --with-secure-transport, --with-amissl, --with-bearssl or --with-rustls to address this.])
  ;;
x1)
  # one SSL backend is enabled
  AC_SUBST(SSL_ENABLED)
  SSL_ENABLED="1"
  AC_MSG_NOTICE([built with one SSL backend])
  ;;
xD)
  # explicitly built without TLS
  ;;
xD*)
  AC_MSG_ERROR([--without-ssl has been set together with an explicit option to use an ssl library
(e.g. --with-openssl, --with-gnutls, --with-wolfssl, --with-mbedtls, --with-nss, --with-schannel, --with-secure-transport, --with-amissl, --with-bearssl, --with-rustls).
Since these are conflicting parameters, verify which is the desired one and drop the other.])
  ;;
*)
  # more than one SSL backend is enabled
  AC_SUBST(SSL_ENABLED)
  SSL_ENABLED="1"
  AC_SUBST(CURL_WITH_MULTI_SSL)
  CURL_WITH_MULTI_SSL="1"
  AC_DEFINE(CURL_WITH_MULTI_SSL, 1, [built with multiple SSL backends])
  AC_MSG_NOTICE([built with multiple SSL backends])
  ;;
esac

if test -n "$ssl_backends"; then
  curl_ssl_msg="enabled ($ssl_backends)"
fi

if test no = "$VALID_DEFAULT_SSL_BACKEND"
then
  if test -n "$SSL_ENABLED"
  then
    AC_MSG_ERROR([Default SSL backend $DEFAULT_SSL_BACKEND not enabled!])
  else
    AC_MSG_ERROR([Default SSL backend requires SSL!])
  fi
elif test yes = "$VALID_DEFAULT_SSL_BACKEND"
then
  AC_DEFINE_UNQUOTED([CURL_DEFAULT_SSL_BACKEND], ["$DEFAULT_SSL_BACKEND"], [Default SSL backend])
fi

dnl **********************************************************************
dnl Check for the CA bundle
dnl **********************************************************************

if test -n "$check_for_ca_bundle"; then
  CURL_CHECK_CA_BUNDLE
fi

dnl **********************************************************************
dnl Check for libpsl
dnl **********************************************************************

AC_ARG_WITH(libpsl,
           AS_HELP_STRING([--without-libpsl],
           [disable support for libpsl cookie checking]),
           with_libpsl=$withval,
           with_libpsl=yes)
if test $with_libpsl != "no"; then
  AC_SEARCH_LIBS(psl_builtin, psl,
    [curl_psl_msg="enabled";
     AC_DEFINE([USE_LIBPSL], [1], [PSL support enabled])
     ],
    [curl_psl_msg="no      (libpsl not found)";
     AC_MSG_WARN([libpsl was not found])
     ]
  )
fi
AM_CONDITIONAL([USE_LIBPSL], [test "$curl_psl_msg" = "enabled"])


dnl **********************************************************************
dnl Check for libgsasl
dnl **********************************************************************

AC_ARG_WITH(libgsasl,
           AS_HELP_STRING([--without-libgsasl],
           [disable libgsasl support for SCRAM]),
           with_libgsasl=$withval,
           with_libgsasl=yes)
if test $with_libgsasl != "no"; then
  AC_SEARCH_LIBS(gsasl_init, gsasl,
    [curl_gsasl_msg="enabled";
     AC_DEFINE([USE_GSASL], [1], [GSASL support enabled])
     ],
    [curl_gsasl_msg="no      (libgsasl not found)";
     AC_MSG_WARN([libgsasl was not found])
     ]
  )
fi
AM_CONDITIONAL([USE_GSASL], [test "$curl_gsasl_msg" = "enabled"])

AC_ARG_WITH(libmetalink,,
  AC_MSG_ERROR([--with-libmetalink no longer works!]))

dnl **********************************************************************
dnl Check for the presence of LIBSSH2 libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for LIBSSH2 files & libraries.
OPT_LIBSSH2=off
AC_ARG_WITH(libssh2,dnl
AS_HELP_STRING([--with-libssh2=PATH],[Where to look for libssh2, PATH points to the libssh2 installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--with-libssh2], [enable libssh2]),
  OPT_LIBSSH2=$withval, OPT_LIBSSH2=no)


OPT_LIBSSH=off
AC_ARG_WITH(libssh,dnl
AS_HELP_STRING([--with-libssh=PATH],[Where to look for libssh, PATH points to the libssh installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--with-libssh], [enable libssh]),
  OPT_LIBSSH=$withval, OPT_LIBSSH=no)

OPT_WOLFSSH=off
AC_ARG_WITH(wolfssh,dnl
AS_HELP_STRING([--with-wolfssh=PATH],[Where to look for wolfssh, PATH points to the wolfSSH installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--with-wolfssh], [enable wolfssh]),
  OPT_WOLFSSH=$withval, OPT_WOLFSSH=no)

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
      LIB_SSH2=`$PKGCONFIG --libs libssh2`
      LD_SSH2=`$PKGCONFIG --libs-only-L libssh2`
      CPP_SSH2=`$PKGCONFIG --cflags-only-I libssh2`
      version=`$PKGCONFIG --modversion libssh2`
      DIR_SSH2=`echo $LD_SSH2 | $SED -e 's/^-L//'`
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

  dnl check for function added in libssh2 version 1.0
  AC_CHECK_LIB(ssh2, libssh2_session_block_directions)

  AC_CHECK_HEADER(libssh2.h,
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
       dnl linker doesn't search through, we need to add it to CURL_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       if test "x$cross_compiling" != "xyes"; then
         CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_SSH2"
         export CURL_LIBRARY_PATH
         AC_MSG_NOTICE([Added $DIR_SSH2 to CURL_LIBRARY_PATH])
       fi
    fi
  else
    dnl no libssh2, revert back to clean variables
    LDFLAGS=$CLEANLDFLAGS
    CPPFLAGS=$CLEANCPPFLAGS
    LIBS=$CLEANLIBS
  fi
elif test X"$OPT_LIBSSH" != Xno; then
  dnl backup the pre-libssh variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  case "$OPT_LIBSSH" in
  yes)
    dnl --with-libssh (without path) used
    CURL_CHECK_PKGCONFIG(libssh)

    if test "$PKGCONFIG" != "no" ; then
      LIB_SSH=`$PKGCONFIG --libs-only-l libssh`
      LD_SSH=`$PKGCONFIG --libs-only-L libssh`
      CPP_SSH=`$PKGCONFIG --cflags-only-I libssh`
      version=`$PKGCONFIG --modversion libssh`
      DIR_SSH=`echo $LD_SSH | $SED -e 's/^-L//'`
    fi

    ;;
  off)
    dnl no --with-libssh option given, just check default places
    ;;
  *)
    dnl use the given --with-libssh spot
    PREFIX_SSH=$OPT_LIBSSH
    ;;
  esac

  dnl if given with a prefix, we set -L and -I based on that
  if test -n "$PREFIX_SSH"; then
    LIB_SSH="-lssh"
    LD_SSH=-L${PREFIX_SSH}/lib$libsuff
    CPP_SSH=-I${PREFIX_SSH}/include
    DIR_SSH=${PREFIX_SSH}/lib$libsuff
  fi

  LDFLAGS="$LDFLAGS $LD_SSH"
  CPPFLAGS="$CPPFLAGS $CPP_SSH"
  LIBS="$LIB_SSH $LIBS"

  AC_CHECK_LIB(ssh, ssh_new)

  AC_CHECK_HEADER(libssh/libssh.h,
    curl_ssh_msg="enabled (libSSH)"
    LIBSSH_ENABLED=1
    AC_DEFINE(USE_LIBSSH, 1, [if libSSH is in use])
    AC_SUBST(USE_LIBSSH, [1])
  )

  if test X"$OPT_LIBSSH" != Xoff &&
     test "$LIBSSH_ENABLED" != "1"; then
    AC_MSG_ERROR([libSSH libs and/or directories were not found where specified!])
  fi

  if test "$LIBSSH_ENABLED" = "1"; then
    if test -n "$DIR_SSH"; then
       dnl when the libssh shared libs were found in a path that the run-time
       dnl linker doesn't search through, we need to add it to CURL_LIBRARY_PATH
       dnl to prevent further configure tests to fail due to this

       if test "x$cross_compiling" != "xyes"; then
         CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_SSH"
         export CURL_LIBRARY_PATH
         AC_MSG_NOTICE([Added $DIR_SSH to CURL_LIBRARY_PATH])
       fi
    fi
  else
    dnl no libssh, revert back to clean variables
    LDFLAGS=$CLEANLDFLAGS
    CPPFLAGS=$CLEANCPPFLAGS
    LIBS=$CLEANLIBS
  fi
elif test X"$OPT_WOLFSSH" != Xno; then
  dnl backup the pre-wolfssh variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"


  if test "$OPT_WOLFSSH" != yes; then
     WOLFCONFIG="$OPT_WOLFSSH/bin/wolfssh-config"
     LDFLAGS="$LDFLAGS `$WOLFCONFIG --libs`"
     CPPFLAGS="$CPPFLAGS `$WOLFCONFIG --cflags`"
  fi

  AC_CHECK_LIB(wolfssh, wolfSSH_Init)

  AC_CHECK_HEADERS(wolfssh/ssh.h,
    curl_ssh_msg="enabled (wolfSSH)"
    WOLFSSH_ENABLED=1
    AC_DEFINE(USE_WOLFSSH, 1, [if wolfSSH is in use])
    AC_SUBST(USE_WOLFSSH, [1])
  )

fi

dnl **********************************************************************
dnl Check for the presence of LIBRTMP libraries and headers
dnl **********************************************************************

dnl Default to compiler & linker defaults for LIBRTMP files & libraries.
OPT_LIBRTMP=off
AC_ARG_WITH(librtmp,dnl
AS_HELP_STRING([--with-librtmp=PATH],[Where to look for librtmp, PATH points to the LIBRTMP installation; when possible, set the PKG_CONFIG_PATH environment variable instead of using this option])
AS_HELP_STRING([--without-librtmp], [disable LIBRTMP]),
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
      DIR_RTMP=`echo $LD_RTMP | $SED -e 's/^-L//'`
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
    LIB_RTMP="-lrtmp"
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
AS_HELP_STRING([--enable-versioned-symbols], [Enable versioned symbols in shared library])
AS_HELP_STRING([--disable-versioned-symbols], [Disable versioned symbols in shared library]),
[ case "$enableval" in
  yes) AC_MSG_RESULT(yes)
    AC_MSG_CHECKING([if libraries can be versioned])
    GLD=`$LD --help < /dev/null 2>/dev/null | grep version-script`
    if test -z "$GLD"; then
        AC_MSG_RESULT(no)
        AC_MSG_WARN([You need an ld version supporting the --version-script option])
    else
        AC_MSG_RESULT(yes)
        if test "x$CURL_WITH_MULTI_SSL" = "x1"; then
          versioned_symbols_flavour="MULTISSL_"
        elif test "x$OPENSSL_ENABLED" = "x1"; then
          versioned_symbols_flavour="OPENSSL_"
        elif test "x$GNUTLS_ENABLED" = "x1"; then
          versioned_symbols_flavour="GNUTLS_"
        elif test "x$NSS_ENABLED" = "x1"; then
          versioned_symbols_flavour="NSS_"
        elif test "x$WOLFSSL_ENABLED" = "x1"; then
          versioned_symbols_flavour="WOLFSSL_"
        elif test "x$SCHANNEL_ENABLED" = "x1"; then
          versioned_symbols_flavour="SCHANNEL_"
        elif test "x$SECURETRANSPORT_ENABLED" = "x1"; then
          versioned_symbols_flavour="SECURE_TRANSPORT_"
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

dnl Update .plist file with current version
AC_SUBST([CURL_PLIST_VERSION],
  ["$CURLVERSION"])

dnl -------------------------------------------------
dnl check winidn option before other IDN libraries
dnl -------------------------------------------------

AC_MSG_CHECKING([whether to enable Windows native IDN (Windows native builds only)])
OPT_WINIDN="default"
AC_ARG_WITH(winidn,
AS_HELP_STRING([--with-winidn=PATH],[enable Windows native IDN])
AS_HELP_STRING([--without-winidn], [disable Windows native IDN]),
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
  clean_CFLAGS="$CFLAGS"
  clean_CPPFLAGS="$CPPFLAGS"
  clean_LDFLAGS="$LDFLAGS"
  clean_LIBS="$LIBS"
  WINIDN_LIBS="-lnormaliz"
  WINIDN_CPPFLAGS=""
  #
  if test "$want_winidn_path" != "default"; then
    dnl path has been specified
    dnl pkg-config not available or provides no info
    WINIDN_LDFLAGS="-L$want_winidn_path/lib$libsuff"
    WINIDN_CPPFLAGS="-I$want_winidn_path/include"
    WINIDN_DIR="$want_winidn_path/lib$libsuff"
  fi
  #
  dnl WinIDN requires a minimum supported OS version of at least Vista (0x0600)
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <windows.h>
    ]],[[
      #if (WINVER < 0x600) && (_WIN32_WINNT < 0x600)
      #error
      #endif
    ]])
  ],[
  ],[
     CFLAGS=`echo $CFLAGS | $SED -e 's/-DWINVER=[[^ ]]*//g'`
     CFLAGS=`echo $CFLAGS | $SED -e 's/-D_WIN32_WINNT=[[^ ]]*//g'`
     CPPFLAGS=`echo $CPPFLAGS | $SED -e 's/-DWINVER=[[^ ]]*//g'`
     CPPFLAGS=`echo $CPPFLAGS | $SED -e 's/-D_WIN32_WINNT=[[^ ]]*//g'`
     WINIDN_CPPFLAGS="$WINIDN_CPPFLAGS -DWINVER=0x0600"
  ])
  #
  CPPFLAGS="$CPPFLAGS $WINIDN_CPPFLAGS"
  LDFLAGS="$LDFLAGS $WINIDN_LDFLAGS"
  LIBS="$WINIDN_LIBS $LIBS"
  #
  AC_MSG_CHECKING([if IdnToUnicode can be linked])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #include <windows.h>
    ]],[[
      IdnToUnicode(0, NULL, 0, NULL, 0);
    ]])
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
    AC_SUBST([IDN_ENABLED], [1])
    curl_idn_msg="enabled (Windows-native)"
  else
    AC_MSG_WARN([Cannot find libraries for IDN support: IDN disabled])
    CFLAGS="$clean_CFLAGS"
    CPPFLAGS="$clean_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS"
    LIBS="$clean_LIBS"
  fi
fi

dnl **********************************************************************
dnl Check for the presence of IDN libraries and headers
dnl **********************************************************************

AC_MSG_CHECKING([whether to build with libidn2])
OPT_IDN="default"
AC_ARG_WITH(libidn2,
AS_HELP_STRING([--with-libidn2=PATH],[Enable libidn2 usage])
AS_HELP_STRING([--without-libidn2],[Disable libidn2 usage]),
  [OPT_IDN=$withval])
if test "x$tst_links_winidn" = "xyes"; then
  want_idn="no"
  AC_MSG_RESULT([no (using winidn instead)])
else
  case "$OPT_IDN" in
    no)
      dnl --without-libidn2 option used
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
      dnl --with-libidn2 option used without path
      want_idn="yes"
      want_idn_path="default"
      AC_MSG_RESULT([yes])
      ;;
    *)
      dnl --with-libidn2 option used with path
      want_idn="yes"
      want_idn_path="$withval"
      AC_MSG_RESULT([yes ($withval)])
      ;;
  esac
fi

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
    CURL_CHECK_PKGCONFIG(libidn2, [$IDN_PCDIR])
    if test "$PKGCONFIG" != "no"; then
      IDN_LIBS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --libs-only-l libidn2 2>/dev/null`
      IDN_LDFLAGS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --libs-only-L libidn2 2>/dev/null`
      IDN_CPPFLAGS=`CURL_EXPORT_PCDIR([$IDN_PCDIR]) dnl
        $PKGCONFIG --cflags-only-I libidn2 2>/dev/null`
      IDN_DIR=`echo $IDN_LDFLAGS | $SED -e 's/^-L//'`
    else
      dnl pkg-config not available or provides no info
      IDN_LIBS="-lidn2"
      IDN_LDFLAGS="-L$want_idn_path/lib$libsuff"
      IDN_CPPFLAGS="-I$want_idn_path/include"
      IDN_DIR="$want_idn_path/lib$libsuff"
    fi
  else
    dnl path not specified
    CURL_CHECK_PKGCONFIG(libidn2)
    if test "$PKGCONFIG" != "no"; then
      IDN_LIBS=`$PKGCONFIG --libs-only-l libidn2 2>/dev/null`
      IDN_LDFLAGS=`$PKGCONFIG --libs-only-L libidn2 2>/dev/null`
      IDN_CPPFLAGS=`$PKGCONFIG --cflags-only-I libidn2 2>/dev/null`
      IDN_DIR=`echo $IDN_LDFLAGS | $SED -e 's/^-L//'`
    else
      dnl pkg-config not available or provides no info
      IDN_LIBS="-lidn2"
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
  CPPFLAGS="$CPPFLAGS $IDN_CPPFLAGS"
  LDFLAGS="$LDFLAGS $IDN_LDFLAGS"
  LIBS="$IDN_LIBS $LIBS"
  #
  AC_MSG_CHECKING([if idn2_lookup_ul can be linked])
  AC_LINK_IFELSE([
    AC_LANG_FUNC_LINK_TRY([idn2_lookup_ul])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_libidn="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_libidn="no"
  ])
  #
  AC_CHECK_HEADERS( idn2.h )

  if test "$tst_links_libidn" = "yes"; then
    AC_DEFINE(HAVE_LIBIDN2, 1, [Define to 1 if you have the `idn2' library (-lidn2).])
    dnl different versions of libidn have different setups of these:

    AC_SUBST([IDN_ENABLED], [1])
    curl_idn_msg="enabled (libidn2)"
    if test -n "$IDN_DIR" -a "x$cross_compiling" != "xyes"; then
      CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$IDN_DIR"
      export CURL_LIBRARY_PATH
      AC_MSG_NOTICE([Added $IDN_DIR to CURL_LIBRARY_PATH])
    fi
  else
    AC_MSG_WARN([Cannot find libraries for IDN support: IDN disabled])
    CPPFLAGS="$clean_CPPFLAGS"
    LDFLAGS="$clean_LDFLAGS"
    LIBS="$clean_LIBS"
  fi
fi

dnl **********************************************************************
dnl Check for nghttp2
dnl **********************************************************************

OPT_H2="yes"

if test "x$disable_http" = "xyes" -o X"$want_hyper" != Xno; then
  # without HTTP or with Hyper, nghttp2 is no use
  OPT_H2="no"
fi

AC_ARG_WITH(nghttp2,
AS_HELP_STRING([--with-nghttp2=PATH],[Enable nghttp2 usage])
AS_HELP_STRING([--without-nghttp2],[Disable nghttp2 usage]),
  [OPT_H2=$withval])
case "$OPT_H2" in
  no)
    dnl --without-nghttp2 option used
    want_nghttp2="no"
    ;;
  yes)
    dnl --with-nghttp2 option used without path
    want_nghttp2="default"
    want_nghttp2_path=""
    want_nghttp2_pkg_config_path=""
    ;;
  *)
    dnl --with-nghttp2 option used with path
    want_nghttp2="yes"
    want_nghttp2_path="$withval"
    want_nghttp2_pkg_config_path="$withval/lib/pkgconfig"
    ;;
esac

if test X"$want_nghttp2" != Xno; then
  dnl backup the pre-nghttp2 variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libnghttp2, $want_nghttp2_pkg_config_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_H2=`CURL_EXPORT_PCDIR([$want_nghttp2_pkg_config_path])
      $PKGCONFIG --libs-only-l libnghttp2`
    AC_MSG_NOTICE([-l is $LIB_H2])

    CPP_H2=`CURL_EXPORT_PCDIR([$want_nghttp2_pkg_config_path]) dnl
      $PKGCONFIG --cflags-only-I libnghttp2`
    AC_MSG_NOTICE([-I is $CPP_H2])

    LD_H2=`CURL_EXPORT_PCDIR([$want_nghttp2_pkg_config_path])
      $PKGCONFIG --libs-only-L libnghttp2`
    AC_MSG_NOTICE([-L is $LD_H2])

    DIR_H2=`echo $LD_H2 | $SED -e 's/^-L//'`
  elif test x"$want_nghttp2_path" != x; then
    LIB_H2="-lnghttp2"
    LD_H2=-L${want_nghttp2_path}/lib$libsuff
    CPP_H2=-I${want_nghttp2_path}/include
    DIR_H2=${want_nghttp2_path}/lib$libsuff
  elif test X"$want_nghttp2" != Xdefault; then
    dnl no nghttp2 pkg-config found and no custom directory specified,
    dnl deal with it
    AC_MSG_ERROR([--with-nghttp2 was specified but could not find libnghttp2 pkg-config file.])
  else
    LIB_H2="-lnghttp2"
  fi

  LDFLAGS="$LDFLAGS $LD_H2"
  CPPFLAGS="$CPPFLAGS $CPP_H2"
  LIBS="$LIB_H2 $LIBS"

  # use nghttp2_session_set_local_window_size to require nghttp2
  # >= 1.12.0
  AC_CHECK_LIB(nghttp2, nghttp2_session_set_local_window_size,
    [
     AC_CHECK_HEADERS(nghttp2/nghttp2.h,
        curl_h2_msg="enabled (nghttp2)"
        NGHTTP2_ENABLED=1
        AC_DEFINE(USE_NGHTTP2, 1, [if nghttp2 is in use])
        AC_SUBST(USE_NGHTTP2, [1])
     )

     CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_H2"
     export CURL_LIBRARY_PATH
     AC_MSG_NOTICE([Added $DIR_H2 to CURL_LIBRARY_PATH])
    ],
      dnl not found, revert back to clean variables
      LDFLAGS=$CLEANLDFLAGS
      CPPFLAGS=$CLEANCPPFLAGS
      LIBS=$CLEANLIBS
  )
fi

dnl **********************************************************************
dnl Check for ngtcp2 (QUIC)
dnl **********************************************************************

OPT_TCP2="no"

if test "x$disable_http" = "xyes"; then
  # without HTTP, ngtcp2 is no use
  OPT_TCP2="no"
fi

AC_ARG_WITH(ngtcp2,
AS_HELP_STRING([--with-ngtcp2=PATH],[Enable ngtcp2 usage])
AS_HELP_STRING([--without-ngtcp2],[Disable ngtcp2 usage]),
  [OPT_TCP2=$withval])
case "$OPT_TCP2" in
  no)
    dnl --without-ngtcp2 option used
    want_tcp2="no"
    ;;
  yes)
    dnl --with-ngtcp2 option used without path
    want_tcp2="default"
    want_tcp2_path=""
    ;;
  *)
    dnl --with-ngtcp2 option used with path
    want_tcp2="yes"
    want_tcp2_path="$withval/lib/pkgconfig"
    ;;
esac

curl_tcp2_msg="no      (--with-ngtcp2)"
if test X"$want_tcp2" != Xno; then
  dnl backup the pre-ngtcp2 variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libngtcp2, $want_tcp2_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_TCP2=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-l libngtcp2`
    AC_MSG_NOTICE([-l is $LIB_TCP2])

    CPP_TCP2=`CURL_EXPORT_PCDIR([$want_tcp2_path]) dnl
      $PKGCONFIG --cflags-only-I libngtcp2`
    AC_MSG_NOTICE([-I is $CPP_TCP2])

    LD_TCP2=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-L libngtcp2`
    AC_MSG_NOTICE([-L is $LD_TCP2])

    LDFLAGS="$LDFLAGS $LD_TCP2"
    CPPFLAGS="$CPPFLAGS $CPP_TCP2"
    LIBS="$LIB_TCP2 $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_TCP2=`echo $LD_TCP2 | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(ngtcp2, ngtcp2_conn_client_new_versioned,
      [
       AC_CHECK_HEADERS(ngtcp2/ngtcp2.h,
          NGTCP2_ENABLED=1
          AC_DEFINE(USE_NGTCP2, 1, [if ngtcp2 is in use])
          AC_SUBST(USE_NGTCP2, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_TCP2"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_TCP2 to CURL_LIBRARY_PATH])
       )
      ],
        dnl not found, revert back to clean variables
        LDFLAGS=$CLEANLDFLAGS
        CPPFLAGS=$CLEANCPPFLAGS
        LIBS=$CLEANLIBS
    )

  else
    dnl no ngtcp2 pkg-config found, deal with it
    if test X"$want_tcp2" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-ngtcp2 without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-ngtcp2 was specified but could not find ngtcp2 pkg-config file.])
    fi
  fi

fi

if test "x$NGTCP2_ENABLED" = "x1" -a "x$OPENSSL_ENABLED" = "x1"; then
  dnl backup the pre-ngtcp2_crypto_openssl variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libngtcp2_crypto_openssl, $want_tcp2_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_NGTCP2_CRYPTO_OPENSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-l libngtcp2_crypto_openssl`
    AC_MSG_NOTICE([-l is $LIB_NGTCP2_CRYPTO_OPENSSL])

    CPP_NGTCP2_CRYPTO_OPENSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path]) dnl
      $PKGCONFIG --cflags-only-I libngtcp2_crypto_openssl`
    AC_MSG_NOTICE([-I is $CPP_NGTCP2_CRYPTO_OPENSSL])

    LD_NGTCP2_CRYPTO_OPENSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-L libngtcp2_crypto_openssl`
    AC_MSG_NOTICE([-L is $LD_NGTCP2_CRYPTO_OPENSSL])

    LDFLAGS="$LDFLAGS $LD_NGTCP2_CRYPTO_OPENSSL"
    CPPFLAGS="$CPPFLAGS $CPP_NGTCP2_CRYPTO_OPENSSL"
    LIBS="$LIB_NGTCP2_CRYPTO_OPENSSL $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_NGTCP2_CRYPTO_OPENSSL=`echo $LD_NGTCP2_CRYPTO_OPENSSL | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(ngtcp2_crypto_openssl, ngtcp2_crypto_recv_client_initial_cb,
      [
       AC_CHECK_HEADERS(ngtcp2/ngtcp2_crypto.h,
          NGTCP2_ENABLED=1
          AC_DEFINE(USE_NGTCP2_CRYPTO_OPENSSL, 1, [if ngtcp2_crypto_openssl is in use])
          AC_SUBST(USE_NGTCP2_CRYPTO_OPENSSL, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_NGTCP2_CRYPTO_OPENSSL"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_NGTCP2_CRYPTO_OPENSSL to CURL_LIBRARY_PATH])
       )
      ],
        dnl not found, revert back to clean variables
        LDFLAGS=$CLEANLDFLAGS
        CPPFLAGS=$CLEANCPPFLAGS
        LIBS=$CLEANLIBS
    )

  else
    dnl no ngtcp2_crypto_openssl pkg-config found, deal with it
    if test X"$want_tcp2" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-ngtcp2 without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-ngtcp2 was specified but could not find ngtcp2_crypto_openssl pkg-config file.])
    fi
  fi
fi

if test "x$NGTCP2_ENABLED" = "x1" -a "x$GNUTLS_ENABLED" = "x1"; then
  dnl backup the pre-ngtcp2_crypto_gnutls variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libngtcp2_crypto_gnutls, $want_tcp2_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_NGTCP2_CRYPTO_GNUTLS=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-l libngtcp2_crypto_gnutls`
    AC_MSG_NOTICE([-l is $LIB_NGTCP2_CRYPTO_GNUTLS])

    CPP_NGTCP2_CRYPTO_GNUTLS=`CURL_EXPORT_PCDIR([$want_tcp2_path]) dnl
      $PKGCONFIG --cflags-only-I libngtcp2_crypto_gnutls`
    AC_MSG_NOTICE([-I is $CPP_NGTCP2_CRYPTO_GNUTLS])

    LD_NGTCP2_CRYPTO_GNUTLS=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-L libngtcp2_crypto_gnutls`
    AC_MSG_NOTICE([-L is $LD_NGTCP2_CRYPTO_GNUTLS])

    LDFLAGS="$LDFLAGS $LD_NGTCP2_CRYPTO_GNUTLS"
    CPPFLAGS="$CPPFLAGS $CPP_NGTCP2_CRYPTO_GNUTLS"
    LIBS="$LIB_NGTCP2_CRYPTO_GNUTLS $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_NGTCP2_CRYPTO_GNUTLS=`echo $LD_NGTCP2_CRYPTO_GNUTLS | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(ngtcp2_crypto_gnutls, ngtcp2_crypto_recv_client_initial_cb,
      [
       AC_CHECK_HEADERS(ngtcp2/ngtcp2_crypto.h,
          NGTCP2_ENABLED=1
          AC_DEFINE(USE_NGTCP2_CRYPTO_GNUTLS, 1, [if ngtcp2_crypto_gnutls is in use])
          AC_SUBST(USE_NGTCP2_CRYPTO_GNUTLS, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_NGTCP2_CRYPTO_GNUTLS"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_NGTCP2_CRYPTO_GNUTLS to CURL_LIBRARY_PATH])
       )
      ],
        dnl not found, revert back to clean variables
        LDFLAGS=$CLEANLDFLAGS
        CPPFLAGS=$CLEANCPPFLAGS
        LIBS=$CLEANLIBS
    )

  else
    dnl no ngtcp2_crypto_gnutls pkg-config found, deal with it
    if test X"$want_tcp2" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-ngtcp2 without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-ngtcp2 was specified but could not find ngtcp2_crypto_gnutls pkg-config file.])
    fi
  fi
fi

if test "x$NGTCP2_ENABLED" = "x1" -a "x$WOLFSSL_ENABLED" = "x1"; then
  dnl backup the pre-ngtcp2_crypto_wolfssl variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libngtcp2_crypto_wolfssl, $want_tcp2_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_NGTCP2_CRYPTO_WOLFSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-l libngtcp2_crypto_wolfssl`
    AC_MSG_NOTICE([-l is $LIB_NGTCP2_CRYPTO_WOLFSSL])

    CPP_NGTCP2_CRYPTO_WOLFSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path]) dnl
      $PKGCONFIG --cflags-only-I libngtcp2_crypto_wolfssl`
    AC_MSG_NOTICE([-I is $CPP_NGTCP2_CRYPTO_WOLFSSL])

    LD_NGTCP2_CRYPTO_WOLFSSL=`CURL_EXPORT_PCDIR([$want_tcp2_path])
      $PKGCONFIG --libs-only-L libngtcp2_crypto_wolfssl`
    AC_MSG_NOTICE([-L is $LD_NGTCP2_CRYPTO_WOLFSSL])

    LDFLAGS="$LDFLAGS $LD_NGTCP2_CRYPTO_WOLFSSL"
    CPPFLAGS="$CPPFLAGS $CPP_NGTCP2_CRYPTO_WOLFSSL"
    LIBS="$LIB_NGTCP2_CRYPTO_WOLFSSL $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_NGTCP2_CRYPTO_WOLFSSL=`echo $LD_NGTCP2_CRYPTO_WOLFSSL | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(ngtcp2_crypto_wolfssl, ngtcp2_crypto_recv_client_initial_cb,
      [
       AC_CHECK_HEADERS(ngtcp2/ngtcp2_crypto.h,
          NGTCP2_ENABLED=1
          AC_DEFINE(USE_NGTCP2_CRYPTO_WOLFSSL, 1, [if ngtcp2_crypto_wolfssl is in use])
          AC_SUBST(USE_NGTCP2_CRYPTO_WOLFSSL, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_NGTCP2_CRYPTO_WOLFSSL"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_NGTCP2_CRYPTO_WOLFSSL to CURL_LIBRARY_PATH])
       )
      ],
        dnl not found, revert back to clean variables
        LDFLAGS=$CLEANLDFLAGS
        CPPFLAGS=$CLEANCPPFLAGS
        LIBS=$CLEANLIBS
    )

  else
    dnl no ngtcp2_crypto_wolfssl pkg-config found, deal with it
    if test X"$want_tcp2" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-ngtcp2 without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-ngtcp2 was specified but could not find ngtcp2_crypto_wolfssl pkg-config file.])
    fi
  fi
fi

dnl **********************************************************************
dnl Check for nghttp3 (HTTP/3 with ngtcp2)
dnl **********************************************************************

OPT_NGHTTP3="yes"

if test "x$NGTCP2_ENABLED" = "x"; then
  # without ngtcp2, nghttp3 is of no use for us
  OPT_NGHTTP3="no"
fi

AC_ARG_WITH(nghttp3,
AS_HELP_STRING([--with-nghttp3=PATH],[Enable nghttp3 usage])
AS_HELP_STRING([--without-nghttp3],[Disable nghttp3 usage]),
  [OPT_NGHTTP3=$withval])
case "$OPT_NGHTTP3" in
  no)
    dnl --without-nghttp3 option used
    want_nghttp3="no"
    ;;
  yes)
    dnl --with-nghttp3 option used without path
    want_nghttp3="default"
    want_nghttp3_path=""
    ;;
  *)
    dnl --with-nghttp3 option used with path
    want_nghttp3="yes"
    want_nghttp3_path="$withval/lib/pkgconfig"
    ;;
esac

curl_http3_msg="no      (--with-nghttp3)"
if test X"$want_nghttp3" != Xno; then
  dnl backup the pre-nghttp3 variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(libnghttp3, $want_nghttp3_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_NGHTTP3=`CURL_EXPORT_PCDIR([$want_nghttp3_path])
      $PKGCONFIG --libs-only-l libnghttp3`
    AC_MSG_NOTICE([-l is $LIB_NGHTTP3])

    CPP_NGHTTP3=`CURL_EXPORT_PCDIR([$want_nghttp3_path]) dnl
      $PKGCONFIG --cflags-only-I libnghttp3`
    AC_MSG_NOTICE([-I is $CPP_NGHTTP3])

    LD_NGHTTP3=`CURL_EXPORT_PCDIR([$want_nghttp3_path])
      $PKGCONFIG --libs-only-L libnghttp3`
    AC_MSG_NOTICE([-L is $LD_NGHTTP3])

    LDFLAGS="$LDFLAGS $LD_NGHTTP3"
    CPPFLAGS="$CPPFLAGS $CPP_NGHTTP3"
    LIBS="$LIB_NGHTTP3 $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_NGHTTP3=`echo $LD_NGHTTP3 | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(nghttp3, nghttp3_conn_client_new_versioned,
      [
       AC_CHECK_HEADERS(nghttp3/nghttp3.h,
          curl_h3_msg="enabled (ngtcp2 + nghttp3)"
          NGHTTP3_ENABLED=1
          AC_DEFINE(USE_NGHTTP3, 1, [if nghttp3 is in use])
          AC_SUBST(USE_NGHTTP3, [1])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_NGHTTP3"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_NGHTTP3 to CURL_LIBRARY_PATH])
          experimental="$experimental HTTP3"
       )
      ],
        dnl not found, revert back to clean variables
        LDFLAGS=$CLEANLDFLAGS
        CPPFLAGS=$CLEANCPPFLAGS
        LIBS=$CLEANLIBS
    )

  else
    dnl no nghttp3 pkg-config found, deal with it
    if test X"$want_nghttp3" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-nghttp3 without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-nghttp3 was specified but could not find nghttp3 pkg-config file.])
    fi
  fi

fi

dnl **********************************************************************
dnl Check for quiche (QUIC)
dnl **********************************************************************

OPT_QUICHE="no"

if test "x$disable_http" = "xyes" -o "x$USE_NGTCP" = "x1"; then
  # without HTTP or with ngtcp2, quiche is no use
  OPT_QUICHE="no"
fi

AC_ARG_WITH(quiche,
AS_HELP_STRING([--with-quiche=PATH],[Enable quiche usage])
AS_HELP_STRING([--without-quiche],[Disable quiche usage]),
  [OPT_QUICHE=$withval])
case "$OPT_QUICHE" in
  no)
    dnl --without-quiche option used
    want_quiche="no"
    ;;
  yes)
    dnl --with-quiche option used without path
    want_quiche="default"
    want_quiche_path=""
    ;;
  *)
    dnl --with-quiche option used with path
    want_quiche="yes"
    want_quiche_path="$withval"
    ;;
esac

if test X"$want_quiche" != Xno; then

  if test "$NGHTTP3_ENABLED" = 1; then
    AC_MSG_ERROR([--with-quiche and --with-ngtcp2 are mutually exclusive])
  fi

  dnl backup the pre-quiche variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  CURL_CHECK_PKGCONFIG(quiche, $want_quiche_path)

  if test "$PKGCONFIG" != "no" ; then
    LIB_QUICHE=`CURL_EXPORT_PCDIR([$want_quiche_path])
      $PKGCONFIG --libs-only-l quiche`
    AC_MSG_NOTICE([-l is $LIB_QUICHE])

    CPP_QUICHE=`CURL_EXPORT_PCDIR([$want_quiche_path]) dnl
      $PKGCONFIG --cflags-only-I quiche`
    AC_MSG_NOTICE([-I is $CPP_QUICHE])

    LD_QUICHE=`CURL_EXPORT_PCDIR([$want_quiche_path])
      $PKGCONFIG --libs-only-L quiche`
    AC_MSG_NOTICE([-L is $LD_QUICHE])

    LDFLAGS="$LDFLAGS $LD_QUICHE"
    CPPFLAGS="$CPPFLAGS $CPP_QUICHE"
    LIBS="$LIB_QUICHE $LIBS"

    if test "x$cross_compiling" != "xyes"; then
      DIR_QUICHE=`echo $LD_QUICHE | $SED -e 's/^-L//'`
    fi
    AC_CHECK_LIB(quiche, quiche_conn_send_ack_eliciting,
      [
       AC_CHECK_HEADERS(quiche.h,
          experimental="$experimental HTTP3"
          AC_MSG_NOTICE([HTTP3 support is experimental])
          curl_h3_msg="enabled (quiche)"
          QUICHE_ENABLED=1
          AC_DEFINE(USE_QUICHE, 1, [if quiche is in use])
          AC_SUBST(USE_QUICHE, [1])
          AC_CHECK_FUNCS([quiche_conn_set_qlog_fd])
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_QUICHE"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $DIR_QUICHE to CURL_LIBRARY_PATH]),
          [],
          [
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
          ]
       )
      ],
        dnl not found, revert back to clean variables
        AC_MSG_ERROR([couldn't use quiche])
    )
  else
    dnl no quiche pkg-config found, deal with it
    if test X"$want_quiche" != Xdefault; then
      dnl To avoid link errors, we do not allow --with-quiche without
      dnl a pkgconfig file
      AC_MSG_ERROR([--with-quiche was specified but could not find quiche pkg-config file.])
    fi
  fi
fi

dnl **********************************************************************
dnl Check for msh3 (QUIC)
dnl **********************************************************************

OPT_MSH3="no"

if test "x$disable_http" = "xyes" -o "x$USE_NGTCP" = "x1"; then
  # without HTTP or with ngtcp2, msh3 is no use
  OPT_MSH3="no"
fi

AC_ARG_WITH(msh3,
AS_HELP_STRING([--with-msh3=PATH],[Enable msh3 usage])
AS_HELP_STRING([--without-msh3],[Disable msh3 usage]),
  [OPT_MSH3=$withval])
case "$OPT_MSH3" in
  no)
    dnl --without-msh3 option used
    want_msh3="no"
    ;;
  yes)
    dnl --with-msh3 option used without path
    want_msh3="default"
    want_msh3_path=""
    ;;
  *)
    dnl --with-msh3 option used with path
    want_msh3="yes"
    want_msh3_path="$withval"
    ;;
esac

if test X"$want_msh3" != Xno; then

  if test "$NGHTTP3_ENABLED" = 1; then
    AC_MSG_ERROR([--with-msh3 and --with-ngtcp2 are mutually exclusive])
  fi

  dnl backup the pre-msh3 variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  if test -n "$want_msh3_path"; then
    LD_MSH3="-L$want_msh3_path/lib"
    CPP_MSH3="-I$want_msh3_path/include"
    DIR_MSH3="$want_msh3_path/lib"
    LDFLAGS="$LDFLAGS $LD_MSH3"
    CPPFLAGS="$CPPFLAGS $CPP_MSH3"
  fi
  LIBS="-lmsh3 $LIBS"

  AC_CHECK_LIB(msh3, MsH3ApiOpen,
    [
    AC_CHECK_HEADERS(msh3.h,
        curl_h3_msg="enabled (msh3)"
        MSH3_ENABLED=1
        AC_DEFINE(USE_MSH3, 1, [if msh3 is in use])
        AC_SUBST(USE_MSH3, [1])
        CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$DIR_MSH3"
        export CURL_LIBRARY_PATH
        AC_MSG_NOTICE([Added $DIR_MSH3 to CURL_LIBRARY_PATH]),
        experimental="$experimental HTTP3"
     )
    ],
      dnl not found, revert back to clean variables
      LDFLAGS=$CLEANLDFLAGS
      CPPFLAGS=$CLEANCPPFLAGS
      LIBS=$CLEANLIBS
  )
fi

dnl **********************************************************************
dnl Check for zsh completion path
dnl **********************************************************************

OPT_ZSH_FPATH=default
AC_ARG_WITH(zsh-functions-dir,
AS_HELP_STRING([--with-zsh-functions-dir=PATH],[Install zsh completions to PATH])
AS_HELP_STRING([--without-zsh-functions-dir],[Do not install zsh completions]),
  [OPT_ZSH_FPATH=$withval])
case "$OPT_ZSH_FPATH" in
  no)
    dnl --without-zsh-functions-dir option used
    ;;
  default|yes)
    dnl --with-zsh-functions-dir option used without path
    ZSH_FUNCTIONS_DIR="$datarootdir/zsh/site-functions"
    AC_SUBST(ZSH_FUNCTIONS_DIR)
    ;;
  *)
    dnl --with-zsh-functions-dir option used with path
    ZSH_FUNCTIONS_DIR="$withval"
    AC_SUBST(ZSH_FUNCTIONS_DIR)
    ;;
esac

dnl **********************************************************************
dnl Check for fish completion path
dnl **********************************************************************

OPT_FISH_FPATH=default
AC_ARG_WITH(fish-functions-dir,
AS_HELP_STRING([--with-fish-functions-dir=PATH],[Install fish completions to PATH])
AS_HELP_STRING([--without-fish-functions-dir],[Do not install fish completions]),
  [OPT_FISH_FPATH=$withval])
case "$OPT_FISH_FPATH" in
  no)
    dnl --without-fish-functions-dir option used
    ;;
  default|yes)
    dnl --with-fish-functions-dir option used without path
    CURL_CHECK_PKGCONFIG(fish)
    if test "$PKGCONFIG" != "no" ; then
      FISH_FUNCTIONS_DIR="$($PKGCONFIG --variable completionsdir fish)"
    else
      FISH_FUNCTIONS_DIR="$datarootdir/fish/vendor_completions.d"
    fi
    AC_SUBST(FISH_FUNCTIONS_DIR)
    ;;
  *)
    dnl --with-fish-functions-dir option used with path
    FISH_FUNCTIONS_DIR="$withval"
    AC_SUBST(FISH_FUNCTIONS_DIR)
    ;;
esac

dnl Now check for the very most basic headers. Then we can use these
dnl ones as default-headers when checking for the rest!
AC_CHECK_HEADERS(
        sys/types.h \
        sys/time.h \
        sys/select.h \
        sys/socket.h \
        sys/ioctl.h \
        sys/uio.h \
        unistd.h \
        stdlib.h \
        arpa/inet.h \
        net/if.h \
        netinet/in.h \
        netinet/in6.h \
        sys/un.h \
        linux/tcp.h \
        netinet/tcp.h \
        netinet/udp.h \
        netdb.h \
        sys/sockio.h \
        sys/stat.h \
        sys/param.h \
        termios.h \
        termio.h \
        fcntl.h \
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
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
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

CURL_CHECK_STRUCT_TIMEVAL
CURL_VERIFY_RUNTIMELIBS

CURL_SIZEOF(size_t)
CURL_SIZEOF(long)
CURL_SIZEOF(int)
CURL_SIZEOF(time_t)
CURL_SIZEOF(off_t)

o=$CPPFLAGS
CPPFLAGS="-I$srcdir/include $CPPFLAGS"
CURL_SIZEOF(curl_off_t, [
#include <curl/system.h>
])
CURL_SIZEOF(curl_socket_t, [
#include <curl/curl.h>
])
CPPFLAGS=$o

AC_CHECK_TYPE(long long,
   [AC_DEFINE(HAVE_LONGLONG, 1,
      [Define to 1 if the compiler supports the 'long long' data type.])]
   longlong="yes"
)

if test ${ac_cv_sizeof_curl_off_t} -lt 8; then
  AC_MSG_ERROR([64 bit curl_off_t is required])
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

# check for sa_family_t
AC_CHECK_TYPE(sa_family_t,
   AC_DEFINE(CURL_SA_FAMILY_T, sa_family_t, [IP address type in sockaddr]),
   [
   # The windows name?
   AC_CHECK_TYPE(ADDRESS_FAMILY,
     AC_DEFINE(CURL_SA_FAMILY_T, ADDRESS_FAMILY, [IP address type in sockaddr]),
     AC_DEFINE(CURL_SA_FAMILY_T, unsigned short, [IP address type in sockaddr]),
    [
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
    ])
   ],
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

# check for suseconds_t
AC_CHECK_TYPE([suseconds_t],[
  AC_DEFINE(HAVE_SUSECONDS_T, 1,
    [Define to 1 if suseconds_t is an available type.])
], ,[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
])

AC_MSG_CHECKING([if time_t is unsigned])
CURL_RUN_IFELSE(
  [
  #include <time.h>
  #include <limits.h>
  time_t t = -1;
  return (t > 0);
  ],[
  AC_MSG_RESULT([yes])
  AC_DEFINE(HAVE_TIME_T_UNSIGNED, 1, [Define this if time_t is unsigned])
],[
  AC_MSG_RESULT([no])
],[
  dnl cross-compiling, most systems are unsigned
  AC_MSG_RESULT([no])
])

CURL_CONFIGURE_PULL_SYS_POLL

TYPE_IN_ADDR_T

TYPE_SOCKADDR_STORAGE

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
CURL_CHECK_FUNC_FREEADDRINFO
CURL_CHECK_FUNC_FSETXATTR
CURL_CHECK_FUNC_FTRUNCATE
CURL_CHECK_FUNC_GETADDRINFO
CURL_CHECK_FUNC_GETHOSTBYNAME
CURL_CHECK_FUNC_GETHOSTBYNAME_R
CURL_CHECK_FUNC_GETHOSTNAME
CURL_CHECK_FUNC_GETPEERNAME
CURL_CHECK_FUNC_GETSOCKNAME
CURL_CHECK_FUNC_IF_NAMETOINDEX
CURL_CHECK_FUNC_GETIFADDRS
CURL_CHECK_FUNC_GMTIME_R
CURL_CHECK_FUNC_INET_NTOP
CURL_CHECK_FUNC_INET_PTON
CURL_CHECK_FUNC_IOCTLSOCKET
CURL_CHECK_FUNC_IOCTLSOCKET_CAMEL
CURL_CHECK_FUNC_MEMRCHR
CURL_CHECK_FUNC_POLL
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
CURL_CHECK_FUNC_STRTOK_R
CURL_CHECK_FUNC_STRTOLL

case $host in
  *msdosdjgpp)
     ac_cv_func_pipe=no
     skipcheck_pipe=yes
     AC_MSG_NOTICE([skip check for pipe on msdosdjgpp])
    ;;
esac

AC_CHECK_DECLS([getpwuid_r], [], [AC_DEFINE(HAVE_DECL_GETPWUID_R_MISSING, 1, "Set if getpwuid_r() declaration is missing")],
        [[#include <pwd.h>
          #include <sys/types.h>]])


AC_CHECK_FUNCS([fnmatch \
  fchmod \
  fork \
  geteuid \
  getpass_r \
  getppid \
  getpwuid \
  getpwuid_r \
  getrlimit \
  gettimeofday \
  if_nametoindex \
  mach_absolute_time \
  pipe \
  sched_yield \
  sendmsg \
  setlocale \
  setmode \
  setrlimit \
  snprintf \
  utime \
  utimes \
  arc4random
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

if test "x$curl_cv_native_windows" != "xyes" &&
   test "x$enable_shared" = "xyes"; then
  build_libhostname=yes
else
  build_libhostname=no
fi
AM_CONDITIONAL(BUILD_LIBHOSTNAME, test x$build_libhostname = xyes)

if test "x$want_ares" != xyes; then
  CURL_CHECK_OPTION_THREADED_RESOLVER
fi

dnl ************************************************************
dnl disable POSIX threads
dnl
AC_MSG_CHECKING([whether to use POSIX threads for threaded resolver])
AC_ARG_ENABLE(pthreads,
AS_HELP_STRING([--enable-pthreads],
               [Enable POSIX threads (default for threaded resolver)])
AS_HELP_STRING([--disable-pthreads],[Disable POSIX threads]),
[ case "$enableval" in
  no)  AC_MSG_RESULT(no)
       want_pthreads=no
       ;;
  *)   AC_MSG_RESULT(yes)
       want_pthreads=yes
       ;;
  esac ], [
       AC_MSG_RESULT(auto)
       want_pthreads=auto
       ]
)

dnl turn off pthreads if rt is disabled
if test "$want_pthreads" != "no"; then
  if test "$want_pthreads" = "yes" && test "$dontwant_rt" = "yes"; then
    AC_MSG_ERROR([options --enable-pthreads and --disable-rt are mutually exclusive])
  fi
  if test "$dontwant_rt" != "no"; then
    dnl if --enable-pthreads was explicit then warn it's being ignored
    if test "$want_pthreads" = "yes"; then
      AC_MSG_WARN([--enable-pthreads Ignored since librt is disabled.])
    fi
    want_pthreads=no
  fi
fi

dnl turn off pthreads if no threaded resolver
if test "$want_pthreads" != "no" && test "$want_thres" != "yes"; then
  want_pthreads=no
fi

dnl detect pthreads
if test "$want_pthreads" != "no"; then
  AC_CHECK_HEADER(pthread.h,
    [ AC_DEFINE(HAVE_PTHREAD_H, 1, [if you have <pthread.h>])
      save_CFLAGS="$CFLAGS"
      dnl When statically linking against boringssl, -lpthread is added to LIBS.
      dnl Make sure to that this does not pass the check below, we really want
      dnl -pthread in CFLAGS as recommended for GCC. This also ensures that
      dnl lib1541 and lib1565 tests are built with these options. Otherwise
      dnl they fail the build since tests/libtest/Makefile.am clears LIBS.
      save_LIBS="$LIBS"

      LIBS=
      dnl Check for libc variants without a separate pthread lib like bionic
      AC_CHECK_FUNC(pthread_create, [USE_THREADS_POSIX=1] )
      LIBS="$save_LIBS"

      dnl on HPUX, life is more complicated...
      case $host in
      *-hp-hpux*)
         dnl it doesn't actually work without -lpthread
         USE_THREADS_POSIX=""
         ;;
      *)
         ;;
      esac

      dnl if it wasn't found without lib, search for it in pthread lib
      if test "$USE_THREADS_POSIX" != "1"
      then
        # assign PTHREAD for pkg-config use
        PTHREAD=" -pthread"

        case $host in
        *-ibm-aix*)
           dnl Check if compiler is xlC
           COMPILER_VERSION=`"$CC" -qversion 2>/dev/null`
           if test x"$COMPILER_VERSION" = "x"; then
             CFLAGS="$CFLAGS -pthread"
           else
             CFLAGS="$CFLAGS -qthreaded"
           fi
           ;;
        powerpc-*amigaos*)
           dnl No -pthread option, but link with -lpthread
           PTHREAD=" -lpthread"
           ;;
        *)
           CFLAGS="$CFLAGS -pthread"
           ;;
        esac
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

dnl threaded resolver check
if test "$want_thres" = "yes" && test "x$USE_THREADS_POSIX" != "x1"; then
  if test "$want_pthreads" = "yes"; then
    AC_MSG_ERROR([--enable-pthreads but pthreads was not found])
  fi
  dnl If native Windows fallback on Win32 threads since no POSIX threads
  if test "$curl_cv_native_windows" = "yes"; then
    USE_THREADS_WIN32=1
    AC_DEFINE(USE_THREADS_WIN32, 1, [if you want Win32 threaded DNS lookup])
    curl_res_msg="Win32 threaded"
  else
    AC_MSG_ERROR([Threaded resolver enabled but no thread library found])
  fi
fi

CURL_CONVERT_INCLUDE_TO_ISYSTEM

dnl ************************************************************
dnl disable verbose text strings
dnl
AC_MSG_CHECKING([whether to enable verbose strings])
AC_ARG_ENABLE(verbose,
AS_HELP_STRING([--enable-verbose],[Enable verbose strings])
AS_HELP_STRING([--disable-verbose],[Disable verbose strings]),
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
AS_HELP_STRING([--enable-sspi],[Enable SSPI])
AS_HELP_STRING([--disable-sspi],[Disable SSPI]),
[ case "$enableval" in
  yes)
       if test "$curl_cv_native_windows" = "yes"; then
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
       if test "x$SCHANNEL_ENABLED" = "x1"; then
         # --with-schannel implies --enable-sspi
         AC_MSG_RESULT(yes)
       else
         AC_MSG_RESULT(no)
       fi
       ;;
  esac ],
       if test "x$SCHANNEL_ENABLED" = "x1"; then
         # --with-schannel implies --enable-sspi
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
AS_HELP_STRING([--enable-crypto-auth],[Enable cryptographic authentication])
AS_HELP_STRING([--disable-crypto-auth],[Disable cryptographic authentication]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_CRYPTO_AUTH, 1, [to disable cryptographic authentication])
       CURL_DISABLE_CRYPTO_AUTH=1
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable NTLM support
dnl
AC_MSG_CHECKING([whether to support NTLM])
AC_ARG_ENABLE(ntlm,
AS_HELP_STRING([--enable-ntlm],[Enable NTLM support])
AS_HELP_STRING([--disable-ntlm],[Disable NTLM support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_NTLM, 1, [to disable NTLM support])
       CURL_DISABLE_NTLM=1
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
AS_HELP_STRING([--enable-tls-srp],[Enable TLS-SRP authentication])
AS_HELP_STRING([--disable-tls-srp],[Disable TLS-SRP authentication]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       want_tls_srp=no
       ;;
  *)   AC_MSG_RESULT(yes)
       want_tls_srp=yes
       ;;
  esac ],
       AC_MSG_RESULT(yes)
       want_tls_srp=yes
)

if test "$want_tls_srp" = "yes" && ( test "x$HAVE_GNUTLS_SRP" = "x1" || test "x$HAVE_OPENSSL_SRP" = "x1") ; then
   AC_DEFINE(USE_TLS_SRP, 1, [Use TLS-SRP authentication])
   USE_TLS_SRP=1
   curl_tls_srp_msg="enabled"
fi

dnl ************************************************************
dnl disable Unix domain sockets support
dnl
AC_MSG_CHECKING([whether to enable Unix domain sockets])
AC_ARG_ENABLE(unix-sockets,
AS_HELP_STRING([--enable-unix-sockets],[Enable Unix domain sockets])
AS_HELP_STRING([--disable-unix-sockets],[Disable Unix domain sockets]),
[ case "$enableval" in
  no)  AC_MSG_RESULT(no)
       want_unix_sockets=no
       ;;
  *)   AC_MSG_RESULT(yes)
       want_unix_sockets=yes
       ;;
  esac ], [
       AC_MSG_RESULT(auto)
       want_unix_sockets=auto
       ]
)
if test "x$want_unix_sockets" != "xno"; then
  if test "x$curl_cv_native_windows" = "xyes"; then
    USE_UNIX_SOCKETS=1
    AC_DEFINE(USE_UNIX_SOCKETS, 1, [Use Unix domain sockets])
    curl_unix_sockets_msg="enabled"
  else
    AC_CHECK_MEMBER([struct sockaddr_un.sun_path], [
      AC_DEFINE(USE_UNIX_SOCKETS, 1, [Use Unix domain sockets])
      AC_SUBST(USE_UNIX_SOCKETS, [1])
      curl_unix_sockets_msg="enabled"
    ], [
      if test "x$want_unix_sockets" = "xyes"; then
        AC_MSG_ERROR([--enable-unix-sockets is not available on this platform!])
      fi
    ], [
      #include <sys/un.h>
    ])
  fi
fi

dnl ************************************************************
dnl disable cookies support
dnl
AC_MSG_CHECKING([whether to support cookies])
AC_ARG_ENABLE(cookies,
AS_HELP_STRING([--enable-cookies],[Enable cookies support])
AS_HELP_STRING([--disable-cookies],[Disable cookies support]),
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
dnl disable socketpair
dnl
AC_MSG_CHECKING([whether to support socketpair])
AC_ARG_ENABLE(socketpair,
AS_HELP_STRING([--enable-socketpair],[Enable socketpair support])
AS_HELP_STRING([--disable-socketpair],[Disable socketpair support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_SOCKETPAIR, 1, [to disable socketpair support])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable HTTP authentication support
dnl
AC_MSG_CHECKING([whether to support HTTP authentication])
AC_ARG_ENABLE(http-auth,
AS_HELP_STRING([--enable-http-auth],[Enable HTTP authentication support])
AS_HELP_STRING([--disable-http-auth],[Disable HTTP authentication support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_HTTP_AUTH, 1, [disable HTTP authentication])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable DoH support
dnl
AC_MSG_CHECKING([whether to support DoH])
AC_ARG_ENABLE(doh,
AS_HELP_STRING([--enable-doh],[Enable DoH support])
AS_HELP_STRING([--disable-doh],[Disable DoH support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_DOH, 1, [disable DoH])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable mime API support
dnl
AC_MSG_CHECKING([whether to support the MIME API])
AC_ARG_ENABLE(mime,
AS_HELP_STRING([--enable-mime],[Enable mime API support])
AS_HELP_STRING([--disable-mime],[Disable mime API support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_MIME, 1, [disable mime API])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable date parsing
dnl
AC_MSG_CHECKING([whether to support date parsing])
AC_ARG_ENABLE(dateparse,
AS_HELP_STRING([--enable-dateparse],[Enable date parsing])
AS_HELP_STRING([--disable-dateparse],[Disable date parsing]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_PARSEDATE, 1, [disable date parsing])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable netrc
dnl
AC_MSG_CHECKING([whether to support netrc parsing])
AC_ARG_ENABLE(netrc,
AS_HELP_STRING([--enable-netrc],[Enable netrc parsing])
AS_HELP_STRING([--disable-netrc],[Disable netrc parsing]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_NETRC, 1, [disable netrc parsing])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable progress-meter
dnl
AC_MSG_CHECKING([whether to support progress-meter])
AC_ARG_ENABLE(progress-meter,
AS_HELP_STRING([--enable-progress-meter],[Enable progress-meter])
AS_HELP_STRING([--disable-progress-meter],[Disable progress-meter]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_PROGRESS_METER, 1, [disable progress-meter])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable shuffle DNS support
dnl
AC_MSG_CHECKING([whether to support DNS shuffling])
AC_ARG_ENABLE(dnsshuffle,
AS_HELP_STRING([--enable-dnsshuffle],[Enable DNS shuffling])
AS_HELP_STRING([--disable-dnsshuffle],[Disable DNS shuffling]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_SHUFFLE_DNS, 1, [disable DNS shuffling])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl disable the curl_easy_options API
dnl
AC_MSG_CHECKING([whether to support curl_easy_option*])
AC_ARG_ENABLE(get-easy-options,
AS_HELP_STRING([--enable-get-easy-options],[Enable curl_easy_options])
AS_HELP_STRING([--disable-get-easy-options],[Disable curl_easy_options]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_GETOPTIONS, 1, [to disable curl_easy_options])
       ;;
  *)   AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl switch on/off alt-svc
dnl
AC_MSG_CHECKING([whether to support alt-svc])
AC_ARG_ENABLE(alt-svc,
AS_HELP_STRING([--enable-alt-svc],[Enable alt-svc support])
AS_HELP_STRING([--disable-alt-svc],[Disable alt-svc support]),
[ case "$enableval" in
  no)
       AC_MSG_RESULT(no)
       AC_DEFINE(CURL_DISABLE_ALTSVC, 1, [disable alt-svc])
       curl_altsvc_msg="no";
       enable_altsvc="no"
       ;;
  *) AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl ************************************************************
dnl switch on/off headers-api
dnl
AC_MSG_CHECKING([whether to support headers-api])
AC_ARG_ENABLE(headers-api,
AS_HELP_STRING([--enable-headers-api],[Enable headers-api support])
AS_HELP_STRING([--disable-headers-api],[Disable headers-api support]),
[ case "$enableval" in
  no) AC_MSG_RESULT(no)
       curl_headers_msg="no      (--enable-headers-api)"
       AC_DEFINE(CURL_DISABLE_HEADERS_API, 1, [disable headers-api])
       ;;
  *)
       AC_MSG_RESULT(yes)
       ;;
  esac ],
       AC_MSG_RESULT(yes)
)

dnl only check for HSTS if there's SSL present
if test -n "$SSL_ENABLED"; then
  dnl ************************************************************
  dnl switch on/off hsts
  dnl
  AC_MSG_CHECKING([whether to support HSTS])
  AC_ARG_ENABLE(hsts,
AS_HELP_STRING([--enable-hsts],[Enable HSTS support])
AS_HELP_STRING([--disable-hsts],[Disable HSTS support]),
  [ case "$enableval" in
    no)
       AC_MSG_RESULT(no)
       hsts="no"
       ;;
    *) AC_MSG_RESULT(yes)
       ;;
    esac ],
       AC_MSG_RESULT($hsts)
  )
else
  AC_MSG_NOTICE([disables HSTS due to lack of SSL])
  hsts="no"
fi

if test "x$hsts" != "xyes"; then
  curl_hsts_msg="no      (--enable-hsts)";
  AC_DEFINE(CURL_DISABLE_HSTS, 1, [disable alt-svc])
fi

dnl *************************************************************
dnl check whether ECH support, if desired, is actually available
dnl
if test "x$want_ech" != "xno"; then
  AC_MSG_CHECKING([whether ECH support is available])

  dnl assume NOT and look for sufficient condition
  ECH_ENABLED=0
  ECH_SUPPORT=''

  dnl OpenSSL with a chosen ECH function should be enough
  dnl so more exhaustive checking seems unnecessary for now
  if test "x$OPENSSL_ENABLED" = "x1"; then
    AC_CHECK_FUNCS(SSL_get_ech_status,
      ECH_SUPPORT="ECH support available (OpenSSL with SSL_get_ech_status)"
      ECH_ENABLED=1)

  dnl add 'elif' chain here for additional implementations
  fi

  dnl now deal with whatever we found
  if test "x$ECH_ENABLED" = "x1"; then
    AC_DEFINE(USE_ECH, 1, [if ECH support is available])
    AC_MSG_RESULT($ECH_SUPPORT)
    experimental="$experimental ECH"
  else
    AC_MSG_ERROR([--enable-ech ignored: No ECH support found])
  fi
fi

dnl *************************************************************
dnl check whether OpenSSL (lookalikes) have SSL_set0_wbio
dnl
if test "x$OPENSSL_ENABLED" = "x1"; then
  AC_CHECK_FUNCS([SSL_set0_wbio])
fi

dnl *************************************************************
dnl WebSockets
dnl
AC_MSG_CHECKING([whether to support WebSockets])
AC_ARG_ENABLE(websockets,
AS_HELP_STRING([--enable-websockets],[Enable WebSockets support])
AS_HELP_STRING([--disable-websockets],[Disable WebSockets support]),
[ case "$enableval" in
  no)
     AC_MSG_RESULT(no)
     ;;
  *)
     if test ${ac_cv_sizeof_curl_off_t} -gt 4; then
         AC_MSG_RESULT(yes)
         curl_ws_msg="enabled"
         AC_DEFINE_UNQUOTED(USE_WEBSOCKETS, [1], [enable websockets support])
         SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS WS"
         if test "x$SSL_ENABLED" = "x1"; then
           SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS WSS"
         fi
         experimental="$experimental Websockets"
     else
         dnl websockets requires >32 bit curl_off_t
         AC_MSG_RESULT(no)
         AC_MSG_WARN([Websockets disabled due to lack of >32 bit curl_off_t])
     fi
     ;;
  esac ],
     AC_MSG_RESULT(no)
)


dnl ************************************************************
dnl hiding of library internal symbols
dnl
CURL_CONFIGURE_SYMBOL_HIDING

dnl
dnl All the library dependencies put into $LIB apply to libcurl only.
dnl
LIBCURL_LIBS="$LIBS$PTHREAD"

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

dnl merge the pkg-config Libs.private field into Libs when static-only
if test "x$enable_shared" = "xno"; then
  LIBCURL_NO_SHARED=$LIBCURL_LIBS
else
  LIBCURL_NO_SHARED=
fi
AC_SUBST(LIBCURL_NO_SHARED)

rm $compilersh

dnl
dnl For keeping supported features and protocols also in pkg-config file
dnl since it is more cross-compile friendly than curl-config
dnl

if test "x$OPENSSL_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSL"
elif test -n "$SSL_ENABLED"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSL"
fi
if test "x$IPV6_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES IPv6"
fi
if test "x$USE_UNIX_SOCKETS" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES UnixSockets"
fi
if test "x$HAVE_LIBZ" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES libz"
fi
if test "x$HAVE_BROTLI" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES brotli"
fi
if test "x$HAVE_ZSTD" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES zstd"
fi
if test "x$USE_ARES" = "x1" -o "x$USE_THREADS_POSIX" = "x1" \
                            -o "x$USE_THREADS_WIN32" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES AsynchDNS"
fi
if test "x$IDN_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES IDN"
fi
if test "x$USE_WINDOWS_SSPI" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SSPI"
fi

if test "x$HAVE_GSSAPI" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES GSS-API"
fi

if test "x$curl_psl_msg" = "xenabled"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES PSL"
fi

if test "x$curl_gsasl_msg" = "xenabled"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES GSASL"
fi

if test "x$enable_altsvc" = "xyes"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES alt-svc"
fi
if test "x$hsts" = "xyes"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES HSTS"
fi

if test "x$CURL_DISABLE_CRYPTO_AUTH" != "x1" -a \
    \( "x$HAVE_GSSAPI" = "x1" -o "x$USE_WINDOWS_SSPI" = "x1" \); then
  SUPPORT_FEATURES="$SUPPORT_FEATURES SPNEGO"
fi

if test "x$CURL_DISABLE_CRYPTO_AUTH" != "x1" -a \
    \( "x$HAVE_GSSAPI" = "x1" -o "x$USE_WINDOWS_SSPI" = "x1" \); then
  SUPPORT_FEATURES="$SUPPORT_FEATURES Kerberos"
fi

use_curl_ntlm_core=no

if test "x$CURL_DISABLE_CRYPTO_AUTH" != "x1" -a \
    "x$CURL_DISABLE_NTLM" != "x1"; then
  if test "x$OPENSSL_ENABLED" = "x1" -o "x$MBEDTLS_ENABLED" = "x1" \
      -o "x$GNUTLS_ENABLED" = "x1" -o "x$NSS_ENABLED" = "x1" \
      -o "x$SECURETRANSPORT_ENABLED" = "x1" \
      -o "x$USE_WIN32_CRYPTO" = "x1" \
      -o "x$WOLFSSL_NTLM" = "x1"; then
    use_curl_ntlm_core=yes
  fi

  if test "x$use_curl_ntlm_core" = "xyes" \
      -o "x$USE_WINDOWS_SSPI" = "x1"; then
    SUPPORT_FEATURES="$SUPPORT_FEATURES NTLM"

    if test "x$CURL_DISABLE_HTTP" != "x1" -a \
        "x$NTLM_WB_ENABLED" = "x1"; then
      SUPPORT_FEATURES="$SUPPORT_FEATURES NTLM_WB"
    fi
  fi
fi

if test "x$USE_TLS_SRP" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES TLS-SRP"
fi

if test "x$USE_NGHTTP2" = "x1" -o "x$USE_HYPER" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES HTTP2"
fi

if test "x$USE_NGTCP2" = "x1" -o "x$USE_QUICHE" = "x1" \
    -o "x$USE_MSH3" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES HTTP3"
fi

if test "x$CURL_WITH_MULTI_SSL" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES MultiSSL"
fi

dnl if not explicitly turned off, HTTPS-proxy comes with some TLS backends
if test "x$https_proxy" != "xno"; then
  if test "x$OPENSSL_ENABLED" = "x1" \
      -o "x$GNUTLS_ENABLED" = "x1" \
      -o "x$NSS_ENABLED" = "x1" \
      -o "x$SECURETRANSPORT_ENABLED" = "x1" \
      -o "x$RUSTLS_ENABLED" = "x1" \
      -o "x$BEARSSL_ENABLED" = "x1" \
      -o "x$SCHANNEL_ENABLED" = "x1" \
      -o "x$GNUTLS_ENABLED" = "x1" \
      -o "x$MBEDTLS_ENABLED" = "x1"; then
    SUPPORT_FEATURES="$SUPPORT_FEATURES HTTPS-proxy"
  elif test "x$WOLFSSL_ENABLED" = "x1" -a "x$WOLFSSL_FULL_BIO" = "x1"; then
    SUPPORT_FEATURES="$SUPPORT_FEATURES HTTPS-proxy"
  fi
fi

if test "x$ECH_ENABLED" = "x1"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES ECH"
fi

if test ${ac_cv_sizeof_curl_off_t} -gt 4; then
  if test ${ac_cv_sizeof_off_t} -gt 4 -o \
     "$curl_win32_file_api" = "win32_large_files"; then
    SUPPORT_FEATURES="$SUPPORT_FEATURES Largefile"
  fi
fi

if test "$tst_atomic" = "yes"; then
  SUPPORT_FEATURES="$SUPPORT_FEATURES threadsafe"
else
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <windows.h>
    ]],[[
      #if (WINVER < 0x600) && (_WIN32_WINNT < 0x600)
      #error
      #endif
    ]])
  ],[
     SUPPORT_FEATURES="$SUPPORT_FEATURES threadsafe"
  ],[
  ])
fi

dnl replace spaces with newlines
dnl sort the lines
dnl replace the newlines back to spaces
SUPPORT_FEATURES=`echo $SUPPORT_FEATURES | tr ' ' '\012' | sort | tr '\012' ' '`
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
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS GOPHERS"
  fi
fi
if test "x$CURL_DISABLE_MQTT" != "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS MQTT"
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
if test "x$CURL_DISABLE_SMB" != "x1" \
    -a "x$use_curl_ntlm_core" = "xyes"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SMB"
  if test "x$SSL_ENABLED" = "x1"; then
    SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SMBS"
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
if test "x$USE_LIBSSH" = "x1"; then
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SCP"
  SUPPORT_PROTOCOLS="$SUPPORT_PROTOCOLS SFTP"
fi
if test "x$USE_WOLFSSH" = "x1"; then
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

SSL_BACKENDS=${ssl_backends}
AC_SUBST(SSL_BACKENDS)

if test "x$want_curldebug_assumed" = "xyes" &&
  test "x$want_curldebug" = "xyes" && test "x$USE_ARES" = "x1"; then
  ac_configure_args="$ac_configure_args --enable-curldebug"
fi

AC_CONFIG_FILES([Makefile \
           docs/Makefile \
           docs/examples/Makefile \
           docs/libcurl/Makefile \
           docs/libcurl/opts/Makefile \
           docs/cmdline-opts/Makefile \
           include/Makefile \
           include/curl/Makefile \
           src/Makefile \
           lib/Makefile \
           scripts/Makefile \
           lib/libcurl.vers \
           lib/libcurl.plist \
           tests/Makefile \
           tests/config \
           tests/certs/Makefile \
           tests/certs/scripts/Makefile \
           tests/data/Makefile \
           tests/server/Makefile \
           tests/libtest/Makefile \
           tests/unit/Makefile \
           tests/http/config.ini \
           tests/http/Makefile \
           tests/http/clients/Makefile \
           packages/Makefile \
           packages/vms/Makefile \
           curl-config \
           libcurl.pc
])
AC_OUTPUT

CURL_GENERATE_CONFIGUREHELP_PM

AC_MSG_NOTICE([Configured to build curl/libcurl:

  Host setup:       ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
   CFLAGS:          ${CFLAGS}
   CPPFLAGS:        ${CPPFLAGS}
   LDFLAGS:         ${LDFLAGS}
   LIBS:            ${LIBS}

  curl version:     ${CURLVERSION}
  SSL:              ${curl_ssl_msg}
  SSH:              ${curl_ssh_msg}
  zlib:             ${curl_zlib_msg}
  brotli:           ${curl_brotli_msg}
  zstd:             ${curl_zstd_msg}
  GSS-API:          ${curl_gss_msg}
  GSASL:            ${curl_gsasl_msg}
  TLS-SRP:          ${curl_tls_srp_msg}
  resolver:         ${curl_res_msg}
  IPv6:             ${curl_ipv6_msg}
  Unix sockets:     ${curl_unix_sockets_msg}
  IDN:              ${curl_idn_msg}
  Build libcurl:    Shared=${enable_shared}, Static=${enable_static}
  Built-in manual:  ${curl_manual_msg}
  --libcurl option: ${curl_libcurl_msg}
  Verbose errors:   ${curl_verbose_msg}
  Code coverage:    ${curl_coverage_msg}
  SSPI:             ${curl_sspi_msg}
  ca cert bundle:   ${ca}${ca_warning}
  ca cert path:     ${capath}${capath_warning}
  ca fallback:      ${with_ca_fallback}
  LDAP:             ${curl_ldap_msg}
  LDAPS:            ${curl_ldaps_msg}
  RTSP:             ${curl_rtsp_msg}
  RTMP:             ${curl_rtmp_msg}
  PSL:              ${curl_psl_msg}
  Alt-svc:          ${curl_altsvc_msg}
  Headers API:      ${curl_headers_msg}
  HSTS:             ${curl_hsts_msg}
  HTTP1:            ${curl_h1_msg}
  HTTP2:            ${curl_h2_msg}
  HTTP3:            ${curl_h3_msg}
  ECH:              ${curl_ech_msg}
  WebSockets:       ${curl_ws_msg}
  Protocols:        ${SUPPORT_PROTOCOLS}
  Features:         ${SUPPORT_FEATURES}
])
if test -n "$experimental"; then
 cat >&2 << _EOF
  WARNING: $experimental enabled but marked EXPERIMENTAL. Use with caution!
_EOF
fi
