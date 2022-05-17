#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

AC_DEFUN([CURL_WITH_WOLFSSL], [
dnl ----------------------------------------------------
dnl check for wolfSSL
dnl ----------------------------------------------------

case "$OPT_WOLFSSL" in
  yes|no)
    wolfpkg=""
    ;;
  *)
    wolfpkg="$withval/lib/pkgconfig"
    ;;
esac

if test "x$OPT_WOLFSSL" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS

  ssl_msg=

  if test X"$OPT_WOLFSSL" != Xno; then

    if test "$OPT_WOLFSSL" = "yes"; then
      OPT_WOLFSSL=""
    fi

    dnl try pkg-config magic
    CURL_CHECK_PKGCONFIG(wolfssl, [$wolfpkg])
    AC_MSG_NOTICE([Check dir $wolfpkg])

    addld=""
    addlib=""
    addcflags=""
    if test "$PKGCONFIG" != "no" ; then
      addlib=`CURL_EXPORT_PCDIR([$wolfpkg])
        $PKGCONFIG --libs-only-l wolfssl`
      addld=`CURL_EXPORT_PCDIR([$wolfpkg])
        $PKGCONFIG --libs-only-L wolfssl`
      addcflags=`CURL_EXPORT_PCDIR([$wolfpkg])
        $PKGCONFIG --cflags-only-I wolfssl`
      version=`CURL_EXPORT_PCDIR([$wolfpkg])
        $PKGCONFIG --modversion wolfssl`
      wolfssllibpath=`echo $addld | $SED -e 's/^-L//'`
    else
      addlib=-lwolfssl
      dnl use system defaults if user does not supply a path
      if test -n "$OPT_WOLFSSL"; then
        addld=-L$OPT_WOLFSSL/lib$libsuff
        addcflags=-I$OPT_WOLFSSL/include
        wolfssllibpath=$OPT_WOLFSSL/lib$libsuff
      fi
    fi

    if test "x$USE_WOLFSSL" != "xyes"; then

      LDFLAGS="$LDFLAGS $addld"
      AC_MSG_NOTICE([Add $addld to LDFLAGS])
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
         AC_MSG_NOTICE([Add $addcflags to CPPFLAGS])
      fi

      my_ac_save_LIBS="$LIBS"
      LIBS="$addlib $LIBS"
      AC_MSG_NOTICE([Add $addlib to LIBS])

      AC_MSG_CHECKING([for wolfSSL_Init in -lwolfssl])
      AC_LINK_IFELSE([
	AC_LANG_PROGRAM([[
/* These aren't needed for detection and confuse WolfSSL.
   They are set up properly later if it is detected.  */
#undef SIZEOF_LONG
#undef SIZEOF_LONG_LONG
#include <wolfssl/ssl.h>
	]],[[
	  return wolfSSL_Init();
	]])
      ],[
         AC_MSG_RESULT(yes)
         AC_DEFINE(USE_WOLFSSL, 1, [if wolfSSL is enabled])
         AC_SUBST(USE_WOLFSSL, [1])
         WOLFSSL_ENABLED=1
         USE_WOLFSSL="yes"
         ssl_msg="WolfSSL"
	 test wolfssl != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       [
         AC_MSG_RESULT(no)
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
         wolfssllibpath=""
       ])
      LIBS="$my_ac_save_LIBS"
    fi

    if test "x$USE_WOLFSSL" = "xyes"; then
      AC_MSG_NOTICE([detected wolfSSL])
      check_for_ca_bundle=1

      dnl wolfssl/ctaocrypt/types.h needs SIZEOF_LONG_LONG defined!
      AX_COMPILE_CHECK_SIZEOF(long long)

      LIBS="$addlib -lm $LIBS"

      dnl WolfSSL needs configure --enable-opensslextra to have *get_peer*
      dnl DES* is needed for NTLM support and lives in the OpenSSL compatibility
      dnl layer
      AC_CHECK_FUNCS(wolfSSL_get_peer_certificate \
                     wolfSSL_UseALPN )

      dnl if this symbol is present, we want the include path to include the
      dnl OpenSSL API root as well
      AC_CHECK_FUNC(wolfSSL_DES_ecb_encrypt,
        [
            AC_DEFINE(HAVE_WOLFSSL_DES_ECB_ENCRYPT, 1,
                      [if you have wolfSSL_DES_ecb_encrypt])
            WOLFSSL_NTLM=1
        ]
        )

      if test -n "$wolfssllibpath"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl CURL_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$wolfssllibpath"
          export CURL_LIBRARY_PATH
          AC_MSG_NOTICE([Added $wolfssllibpath to CURL_LIBRARY_PATH])
        fi
      fi

    fi

  fi dnl wolfSSL not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi

])
