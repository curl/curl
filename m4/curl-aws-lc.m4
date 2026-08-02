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

dnl File version for 'aclocal' use. Keep it a single number.
dnl serial 5

dnl **********************************************************************
dnl Check for AWS-LC libraries and headers
dnl **********************************************************************

AC_DEFUN([CURL_WITH_AWS_LC], [
if test "x$OPT_AWS_LC" != "xno"; then
  ssl_msg=

  dnl backup the pre-detection variables
  CLEANLDFLAGS="$LDFLAGS"
  CLEANLDFLAGSPC="$LDFLAGSPC"
  CLEANCPPFLAGS="$CPPFLAGS"
  CLEANLIBS="$LIBS"

  dnl This is for MSYS/MinGW
  case $host in
    *-*-msys* | *-*-mingw*)
      AC_MSG_CHECKING([for gdi32])
      my_ac_save_LIBS=$LIBS
      LIBS="-lgdi32 $LIBS"
      AC_LINK_IFELSE([ AC_LANG_PROGRAM([[
        #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
        #endif
        #include <windef.h>
        #include <wingdi.h>
        ]],
        [[
          GdiFlush();
        ]])],
        [ dnl worked!
        AC_MSG_RESULT([yes])],
        [ dnl failed, restore LIBS
        LIBS=$my_ac_save_LIBS
        AC_MSG_RESULT(no)]
        )
      ;;
  esac

  case "$OPT_AWS_LC" in
    yes)
      dnl --with-aws-lc (without path) used
      PKGTEST="yes"
      PREFIX_AWS_LC=
      ;;
    *)
      dnl check the given --with-aws-lc spot
      PKGTEST="no"
      PREFIX_AWS_LC=$OPT_AWS_LC

      dnl Try pkg-config even when cross-compiling.  Since we
      dnl specify PKG_CONFIG_LIBDIR we are only looking where
      dnl the user told us to look
      AWS_LC_PCDIR="$OPT_AWS_LC/lib/pkgconfig"
      if test -f "$AWS_LC_PCDIR/aws-lc.pc"; then
        AC_MSG_NOTICE([PKG_CONFIG_LIBDIR is set to "$AWS_LC_PCDIR"])
        PKGTEST="yes"
      fi

      if test "$PKGTEST" != "yes"; then
        dnl try lib64 instead
        AWS_LC_PCDIR="$OPT_AWS_LC/lib64/pkgconfig"
        if test -f "$AWS_LC_PCDIR/aws-lc.pc"; then
          AC_MSG_NOTICE([PKG_CONFIG_LIBDIR is set to "$AWS_LC_PCDIR"])
          PKGTEST="yes"
        fi
      fi

      if test "$PKGTEST" != "yes" &&
         test ! -f "$PREFIX_AWS_LC/include/aws-lc/openssl/ssl.h"; then
        AC_MSG_ERROR([$PREFIX_AWS_LC is a bad --with-aws-lc prefix!])
      fi

      dnl in case pkg-config comes up empty, use what we got
      dnl via --with-aws-lc
      LIB_AWS_LC="$PREFIX_AWS_LC/lib$libsuff"
      if test "$PREFIX_AWS_LC" != "/usr"; then
        SSL_LDFLAGS="-L$LIB_AWS_LC"
        SSL_CPPFLAGS="-I$PREFIX_AWS_LC/include/aws-lc"
      fi
      ;;
  esac

  if test "$PKGTEST" = "yes"; then

    CURL_CHECK_PKGCONFIG(aws-lc, [$AWS_LC_PCDIR])

    if test "$PKGCONFIG" != "no"; then
      SSL_LIBS=`CURL_EXPORT_PCDIR([$AWS_LC_PCDIR])
        $PKGCONFIG --libs-only-l --libs-only-other aws-lc 2>/dev/null`

      SSL_LDFLAGS=`CURL_EXPORT_PCDIR([$AWS_LC_PCDIR])
        $PKGCONFIG --libs-only-L aws-lc 2>/dev/null`

      SSL_CPPFLAGS=`CURL_EXPORT_PCDIR([$AWS_LC_PCDIR])
        $PKGCONFIG --cflags-only-I aws-lc 2>/dev/null`

      AC_MSG_NOTICE([pkg-config: SSL_LIBS: "$SSL_LIBS"])
      AC_MSG_NOTICE([pkg-config: SSL_LDFLAGS: "$SSL_LDFLAGS"])
      AC_MSG_NOTICE([pkg-config: SSL_CPPFLAGS: "$SSL_CPPFLAGS"])

      LIB_AWS_LC=`echo $SSL_LDFLAGS | sed -e 's/^-L//'`

      dnl use the values pkg-config reported.  This is here
      dnl instead of below with CPPFLAGS and LDFLAGS because we only
      dnl learn about this via pkg-config.  If we only have
      dnl the argument to --with-openssl we do not know what
      dnl additional libs may be necessary.  Hope that we
      dnl do not need any.
      LIBS="$SSL_LIBS $LIBS"
    fi
  fi

  dnl finally, set flags to use SSL
  CPPFLAGS="$CPPFLAGS $SSL_CPPFLAGS"
  LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
  LDFLAGSPC="$LDFLAGSPC $SSL_LDFLAGS"

  AC_CHECK_LIB(crypto-awslc, HMAC_Update,[
    HAVECRYPTO_AWSLC="yes"
    LIBS="-lcrypto-awslc $LIBS"
    ],[
    if test -n "$LIB_AWS_LC"; then
      LDFLAGS="$CLEANLDFLAGS -L$LIB_AWS_LC"
      LDFLAGSPC="$CLEANLDFLAGSPC -L$LIB_AWS_LC"
    fi
    if test "$PKGCONFIG" = "no" && test -n "$PREFIX_AWS_LC"; then
      dnl only set this if pkg-config was not used
      CPPFLAGS="$CLEANCPPFLAGS -I$PREFIX_AWS_LC/include/aws-lc"
    fi
    dnl Linking previously failed, try extra paths from --with-aws-lc or
    dnl pkg-config.  Use a different function name to avoid reusing the earlier
    dnl cached result.
    AC_CHECK_LIB(crypto-awslc, HMAC_Init_ex,[
      HAVECRYPTO_AWSLC="yes"
      LIBS="-lcrypto-awslc $LIBS"], [

      dnl still no, but what about with -ldl?
      AC_MSG_CHECKING([AWS-LC linking with -ldl])
      LIBS="-lcrypto-awslc $CLEANLIBS -ldl"
      AC_LINK_IFELSE([ AC_LANG_PROGRAM([[
        #include <openssl/err.h>
      ]], [[
        ERR_clear_error();
      ]]) ],
      [
        AC_MSG_RESULT(yes)
        HAVECRYPTO_AWSLC="yes"
      ],
      [
        AC_MSG_RESULT(no)
        dnl ok, so what about both -ldl and -lpthread?
        dnl This may be necessary for static libraries.

        AC_MSG_CHECKING([AWS-LC linking with -ldl and -lpthread])
        LIBS="-lcrypto-awslc $CLEANLIBS -ldl -lpthread"
        AC_LINK_IFELSE([
          AC_LANG_PROGRAM([[
          #include <openssl/err.h>
        ]], [[
          ERR_clear_error();
        ]])],
        [
          AC_MSG_RESULT(yes)
          HAVECRYPTO_AWSLC="yes"
        ],
        [
          AC_MSG_RESULT(no)
          LDFLAGS="$CLEANLDFLAGS"
          LDFLAGSPC="$CLEANLDFLAGSPC"
          CPPFLAGS="$CLEANCPPFLAGS"
          LIBS="$CLEANLIBS"
        ])
      ])
    ])
  ])

  if test "$HAVECRYPTO_AWSLC" = "yes"; then
    dnl This is only reasonable to do if crypto actually is there: check for
    dnl SSL libs NOTE: it is important to do this AFTER the crypto lib

    AC_CHECK_LIB(ssl-awslc, SSL_connect)

    if test "$ac_cv_lib_ssl_awslc_SSL_connect" = "yes"; then
      dnl Have the libraries--check for AWS-LC headers
      AC_CHECK_HEADERS(openssl/rsa.h openssl/crypto.h openssl/pem.h openssl/ssl.h openssl/err.h,
        ssl_msg="AWS-LC"
        test "aws-lc" != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        AWS_LC_ENABLED=1
        AC_DEFINE(USE_OPENSSL, 1, [if AWS-LC is in use, similar enough to OpenSSL codepaths])
        AC_DEFINE(USE_AWS_LC, 1, [if AWS-LC is in use]))
    fi

    if test "$AWS_LC_ENABLED" != "1"; then
      LIBS="$CLEANLIBS"
      AC_MSG_ERROR([AWS-LC libs and/or directories were not found!])
    fi
  fi

  if test "$AWS_LC_ENABLED" = "1"; then
    dnl These can only exist if OpenSSL exists

    AC_MSG_CHECKING([for AWS-LC])
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
        #include <openssl/base.h>
        ]],[[
        #ifndef OPENSSL_IS_AWSLC
        #error not AWS-LC
        #endif
      ]])
    ],[
      AC_MSG_RESULT([yes])
      ssl_msg="AWS-LC"
      OPENSSL_IS_AWSLC=1
    ],[
      AC_MSG_RESULT([no])
    ])
  fi

  dnl is this OpenSSL (fork) providing the original QUIC API?
  AC_CHECK_FUNCS([SSL_set_quic_use_legacy_codepoint], [QUIC_ENABLED=yes])
  if test "$QUIC_ENABLED" = "yes"; then
    AC_MSG_NOTICE([AWS-LC speaks QUIC API])
  else
    AC_CHECK_FUNCS([SSL_set_quic_tls_cbs], [QUIC_ENABLED=yes])
    if test "$QUIC_ENABLED" = "yes"; then
      AC_MSG_NOTICE([AWS-LC with QUIC APIv2])
      OPENSSL_QUIC_API2=1
    else
      AC_MSG_NOTICE([AWS-LC version does not speak any known QUIC API])
    fi
  fi

  if test "$AWS_LC_ENABLED" = "1"; then
    if test -n "$LIB_AWS_LC"; then
      dnl when the SSL shared libs were found in a path that the runtime
      dnl linker does not search through, we need to add it to CURL_LIBRARY_PATH
      dnl to prevent further configure tests to fail due to this
      if test "$cross_compiling" != "yes"; then
        CURL_LIBRARY_PATH="$CURL_LIBRARY_PATH:$LIB_AWS_LC"
        export CURL_LIBRARY_PATH
        AC_MSG_NOTICE([Added $LIB_AWS_LC to CURL_LIBRARY_PATH])
      fi
    fi
    check_for_ca_bundle=1
    LIBCURL_PC_REQUIRES_PRIVATE="$LIBCURL_PC_REQUIRES_PRIVATE aws-lc"
  fi

  if test "$AWS_LC_ENABLED" != "1"; then
    AC_MSG_NOTICE([OPT_AWS_LC: $OPT_AWS_LC])
    AC_MSG_NOTICE([AWS_LC_ENABLED: $AWS_LC_ENABLED])
    AC_MSG_ERROR([--with-aws-lc was given but AWS-LC could not be detected])
  fi

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi dnl AWS-LC not disabled

if test "$AWS_LC_ENABLED" = "1"; then
  dnl ---
  dnl We check AWS-LC for DES support.
  dnl ---
  AC_MSG_CHECKING([for DES support in AWS-LC])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #ifndef OPENSSL_SUPPRESS_DEPRECATED
      #define OPENSSL_SUPPRESS_DEPRECATED
      #endif
      #include <openssl/des.h>
    ]],[[
      DES_ecb_encrypt(0, 0, 0, DES_ENCRYPT);
    ]])
  ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_DES_ECB_ENCRYPT, 1, [if you have the function DES_ecb_encrypt])
    HAVE_DES_ECB_ENCRYPT=1
  ],[
    AC_MSG_RESULT([no])
  ])

  dnl ---
  dnl Whether the AWS-LC configuration is loaded automatically
  dnl ---
  AC_ARG_ENABLE(aws-lc-auto-load-config,
AS_HELP_STRING([--enable-aws-lc-auto-load-config],[Enable automatic loading of AWS-LC configuration])
AS_HELP_STRING([--disable-aws-lc-auto-load-config],[Disable automatic loading of AWS-LC configuration]),
  [ if test "x$enableval" = "xno"; then
      AC_MSG_NOTICE([automatic loading of AWS-LC configuration disabled])
      AC_DEFINE(CURL_DISABLE_AWS_LC_AUTO_LOAD_CONFIG, 1, [if the AWS-LC configuration is not loaded automatically])
    fi
  ])
fi
])
