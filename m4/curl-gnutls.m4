#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#***************************************************************************

dnl ----------------------------------------------------
dnl check for GnuTLS
dnl ----------------------------------------------------

AC_DEFUN([CURL_WITH_GNUTLS], [
if test "x$OPT_GNUTLS" != xno; then
  ssl_msg=

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
        gtlslib=`echo $addld | $SED -e 's/^-L//'`
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

      dnl this function is selected since it was introduced in 3.1.10
      AC_CHECK_LIB(gnutls, gnutls_x509_crt_get_dn2,
       [
       AC_DEFINE(USE_GNUTLS, 1, [if GnuTLS is enabled])
       AC_SUBST(USE_GNUTLS, [1])
       GNUTLS_ENABLED=1
       USE_GNUTLS="yes"
       ssl_msg="GnuTLS"
       test gnutls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       [
         LIBS="$CLEANLIBS"
         CPPFLAGS="$CLEANCPPFLAGS"
       ])

      if test "x$USE_GNUTLS" = "xyes"; then
        AC_MSG_NOTICE([detected GnuTLS version $version])
        check_for_ca_bundle=1
        if test -n "$gtlslib"; then
          dnl when shared libs were found in a path that the run-time
          dnl linker doesn't search through, we need to add it to
          dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
          dnl due to this
          if test "x$cross_compiling" != "xyes"; then
            CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$gtlslib"
            export CURL_LIBRARY_PATH
            AC_MSG_NOTICE([Added $gtlslib to CURL_LIBRARY_PATH])
          fi
        fi
      fi

    fi

  fi dnl GNUTLS not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi

dnl ---
dnl Check which crypto backend GnuTLS uses
dnl ---

if test "$GNUTLS_ENABLED" = "1"; then
  USE_GNUTLS_NETTLE=
  # First check if we can detect either crypto library via transitive linking
  AC_CHECK_LIB(gnutls, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])

  # If not, try linking directly to both of them to see if they are available
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_CHECK_LIB(nettle, nettle_MD5Init, [ USE_GNUTLS_NETTLE=1 ])
  fi
  if test "$USE_GNUTLS_NETTLE" = ""; then
    AC_MSG_ERROR([GnuTLS found, but nettle was not found])
  fi
  LIBS="-lnettle $LIBS"
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

])
