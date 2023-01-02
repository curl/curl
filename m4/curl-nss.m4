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

AC_DEFUN([CURL_WITH_NSS], [
if test "x$OPT_NSS" != xno; then
  ssl_msg=

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
      NSS_PCDIR="$OPT_NSS/lib/pkgconfig"
      if test -f "$NSS_PCDIR/nss.pc"; then
        CURL_CHECK_PKGCONFIG(nss, [$NSS_PCDIR])
        if test "$PKGCONFIG" != "no" ; then
          addld=`CURL_EXPORT_PCDIR([$NSS_PCDIR]) $PKGCONFIG --libs-only-L nss`
          addlib=`CURL_EXPORT_PCDIR([$NSS_PCDIR]) $PKGCONFIG --libs-only-l nss`
          addcflags=`CURL_EXPORT_PCDIR([$NSS_PCDIR]) $PKGCONFIG --cflags nss`
          version=`CURL_EXPORT_PCDIR([$NSS_PCDIR]) $PKGCONFIG --modversion nss`
          nssprefix=`CURL_EXPORT_PCDIR([$NSS_PCDIR]) $PKGCONFIG --variable=prefix nss`
        fi
      fi
    fi

    if test -z "$addlib"; then
      # Without pkg-config, we'll kludge in some defaults
      AC_MSG_WARN([Using hard-wired libraries and compilation flags for NSS.])
      addld="-L$OPT_NSS/lib"
      addlib="-lssl3 -lsmime3 -lnss3 -lplds4 -lplc4 -lnspr4"
      addcflags="-I$OPT_NSS/include"
      version="unknown"
      nssprefix=$OPT_NSS
    fi

    CLEANLDFLAGS="$LDFLAGS"
    CLEANLIBS="$LIBS"
    CLEANCPPFLAGS="$CPPFLAGS"

    LDFLAGS="$addld $LDFLAGS"
    LIBS="$addlib $LIBS"
    if test "$addcflags" != "-I/usr/include"; then
       CPPFLAGS="$CPPFLAGS $addcflags"
    fi

    dnl The function SSL_VersionRangeSet() is needed to enable TLS > 1.0
    AC_CHECK_LIB(nss3, SSL_VersionRangeSet,
     [
     AC_DEFINE(USE_NSS, 1, [if NSS is enabled])
     AC_SUBST(USE_NSS, [1])
     USE_NSS="yes"
     NSS_ENABLED=1
     ssl_msg="NSS"
     test nss != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
     ],
     [
       LDFLAGS="$CLEANLDFLAGS"
       LIBS="$CLEANLIBS"
       CPPFLAGS="$CLEANCPPFLAGS"
     ])

    if test "x$USE_NSS" = "xyes"; then
      AC_MSG_NOTICE([detected NSS version $version])

      dnl PK11_CreateManagedGenericObject() was introduced in NSS 3.34 because
      dnl PK11_DestroyGenericObject() does not release resources allocated by
      dnl PK11_CreateGenericObject() early enough.
      AC_CHECK_FUNC(PK11_CreateManagedGenericObject,
        [
          AC_DEFINE(HAVE_PK11_CREATEMANAGEDGENERICOBJECT, 1,
                    [if you have the PK11_CreateManagedGenericObject function])
        ])

      dnl needed when linking the curl tool without USE_EXPLICIT_LIB_DEPS
      NSS_LIBS=$addlib
      AC_SUBST([NSS_LIBS])

      dnl when shared libs were found in a path that the run-time
      dnl linker doesn't search through, we need to add it to
      dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
      dnl due to this
      if test "x$cross_compiling" != "xyes"; then
        CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$nssprefix/lib$libsuff"
        export CURL_LIBRARY_PATH
        AC_MSG_NOTICE([Added $nssprefix/lib$libsuff to CURL_LIBRARY_PATH])
      fi

    fi dnl NSS found

  fi dnl NSS not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi

])
