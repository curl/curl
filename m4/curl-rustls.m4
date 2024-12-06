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

AC_DEFUN([CURL_WITH_RUSTLS], [
dnl ----------------------------------------------------
dnl check for Rustls
dnl ----------------------------------------------------

if test "x$OPT_RUSTLS" != xno; then
  ssl_msg=

  dnl backup the pre-ssl variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANLDFLAGSPC="$LDFLAGSPC"
  CLEANCPPFLAGS="$CPPFLAGS"

  ## NEW CODE

  dnl use pkg-config unless we have been given a path
  dnl even then, try pkg-config first

  case "$OPT_RUSTLS" in
    yes)
      dnl --with-rustls (without path) used
      PKGTEST="yes"
      PREFIX_RUSTLS=
      ;;
    *)
      dnl check the provided --with-rustls path
      PKGTEST="no"
      PREFIX_RUSTLS=$OPT_RUSTLS

      dnl Try pkg-config even when cross-compiling.  Since we
      dnl specify PKG_CONFIG_LIBDIR we are only looking where
      dnl the user told us to look

      RUSTLS_PCDIR="$PREFIX_RUSTLS/lib/pkgconfig"
      if test -f "$RUSTLS_PCDIR/rustls.pc"; then
        AC_MSG_NOTICE([PKG_CONFIG_LIBDIR will be set to "$RUSTLS_PCDIR"])
        PKGTEST="yes"
      fi

      if test "$PKGTEST" != "yes"; then
        # try lib64 instead
        RUSTLS_PCDIR="$PREFIX_RUSTLS/lib64/pkgconfig"
        if test -f "$RUSTLS_PCDIR/rustls.pc"; then
          AC_MSG_NOTICE([PKG_CONFIG_LIBDIR will be set to "$RUSTLS_PCDIR"])
          PKGTEST="yes"
        fi
      fi

      if test "$PKGTEST" != "yes"; then
        dnl pkg-config came up empty, use what we got
        dnl via --with-rustls

        addld=-L$PREFIX_RUSTLS/lib$libsuff
        addcflags=-I$PREFIX_RUSTLS/include

        LDFLAGS="$LDFLAGS $addld"
        LDFLAGSPC="$LDFLAGSPC $addld"
        if test "$addcflags" != "-I/usr/include"; then
            CPPFLAGS="$CPPFLAGS $addcflags"
        fi

        case $host in
          *-apple-*)
            RUSTLS_LDFLAGS="-framework Security -framework Foundation"
            ;;
          *)
            RUSTLS_LDFLAGS="-lpthread -ldl -lm"
            ;;
        esac
        AC_CHECK_LIB(rustls, rustls_connection_read,
          [
          AC_DEFINE(USE_RUSTLS, 1, [if Rustls is enabled])
          RUSTLS_ENABLED=1
          USE_RUSTLS="yes"
          ssl_msg="rustls"
          test rustls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
          ],
          AC_MSG_ERROR([--with-rustls was specified but could not find Rustls.]),
          $RUSTLS_LDFLAGS)

        LIB_RUSTLS="$PREFIX_RUSTLS/lib$libsuff"
        if test "$PREFIX_RUSTLS" != "/usr" ; then
          SSL_LDFLAGS="-L$LIB_RUSTLS $RUSTLS_LDFLAGS"
          SSL_CPPFLAGS="-I$PREFIX_RUSTLS/include"
        fi
      fi
      ;;
  esac

  link_pkgconfig=''

  if test "$PKGTEST" = "yes"; then

    CURL_CHECK_PKGCONFIG(rustls, [$RUSTLS_PCDIR])

    if test "$PKGCONFIG" != "no" ; then
      SSL_LIBS=`CURL_EXPORT_PCDIR([$RUSTLS_PCDIR]) dnl
        $PKGCONFIG --libs-only-l --libs-only-other rustls 2>/dev/null`

      SSL_LDFLAGS=`CURL_EXPORT_PCDIR([$RUSTLS_PCDIR]) dnl
        $PKGCONFIG --libs-only-L rustls 2>/dev/null`

      SSL_CPPFLAGS=`CURL_EXPORT_PCDIR([$RUSTLS_PCDIR]) dnl
        $PKGCONFIG --cflags-only-I rustls 2>/dev/null`

      AC_MSG_NOTICE([pkg-config: SSL_LIBS: "$SSL_LIBS"])
      AC_MSG_NOTICE([pkg-config: SSL_LDFLAGS: "$SSL_LDFLAGS"])
      AC_MSG_NOTICE([pkg-config: SSL_CPPFLAGS: "$SSL_CPPFLAGS"])

      LIB_RUSTLS=`echo $SSL_LDFLAGS | sed -e 's/^-L//'`

      dnl use the values pkg-config reported.  This is here
      dnl instead of below with CPPFLAGS and LDFLAGS because we only
      dnl learn about this via pkg-config.  If we only have
      dnl the argument to --with-rustls we don't know what
      dnl additional libs may be necessary.  Hope that we
      dnl don't need any.
      LIBS="$SSL_LIBS $LIBS"
      link_pkgconfig=1
      ssl_msg="rustls"
      AC_DEFINE(USE_RUSTLS, 1, [if Rustls is enabled])
      USE_RUSTLS="yes"
      RUSTLS_ENABLED=1
      test rustls != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
    else
      AC_MSG_ERROR([pkg-config: Could not find Rustls])
    fi

  else
    dnl we did not use pkg-config, so we need to add the
    dnl Rustls lib to LIBS
    LIBS="-lrustls -lpthread -ldl -lm $LIBS"
  fi

  dnl finally, set flags to use this TLS backend
  CPPFLAGS="$CLEANCPPFLAGS $SSL_CPPFLAGS"
  LDFLAGS="$CLEANLDFLAGS $SSL_LDFLAGS"
  LDFLAGSPC="$CLEANLDFLAGSPC $SSL_LDFLAGS"

  if test "x$USE_RUSTLS" = "xyes"; then
    AC_MSG_NOTICE([detected Rustls])
    check_for_ca_bundle=1

    if test -n "$LIB_RUSTLS"; then
      dnl when shared libs were found in a path that the run-time
      dnl linker does not search through, we need to add it to
      dnl CURL_LIBRARY_PATH so that further configure tests do not
      dnl fail due to this
      if test "x$cross_compiling" != "xyes"; then
        CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$LIB_RUSTLS"
        export CURL_LIBRARY_PATH
        AC_MSG_NOTICE([Added $LIB_RUSTLS to CURL_LIBRARY_PATH])
      fi
    fi
    if test -n "$link_pkgconfig"; then
      LIBCURL_PC_REQUIRES_PRIVATE="$LIBCURL_PC_REQUIRES_PRIVATE rustls"
    fi
  fi

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"

  if test X"$OPT_RUSTLS" != Xno &&
    test "$RUSTLS_ENABLED" != "1"; then
    AC_MSG_NOTICE([OPT_RUSTLS: $OPT_RUSTLS])
    AC_MSG_NOTICE([RUSTLS_ENABLED: $RUSTLS_ENABLED])
    AC_MSG_ERROR([--with-rustls was given but Rustls could not be detected])
  fi
fi
])

RUSTLS_ENABLED
