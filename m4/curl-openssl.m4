#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

# File version for 'aclocal' use. Keep it a single number.
# serial 2


dnl CURL_CHECK_OPENSSL_ADD_ALL_ALGORITHMS_API
dnl -------------------------------------------------
dnl Link time verification check of which API is
dnl used for OpenSSL_add_all_algorithms function.
dnl HAVE_OPENSSL_ADD_ALL_ALGORITHMS_API gets defined as
dnl apprpriate only for systems which actually run the
dnl configure script. Config files generated manually
dnl or in any other way shall not define this.

AC_DEFUN([CURL_CHECK_OPENSSL_ADD_ALL_ALGORITHMS_API], [
  #
  tst_openssl_add_all_algorithms_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL_add_all_algorithms API])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      OPENSSL_add_all_algorithms_conf();
      OPENSSL_add_all_algorithms_noconf();
    ]])
  ],[
    tst_openssl_add_all_algorithms_api="0x097"
  ])
  if test "$tst_openssl_add_all_algorithms_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        OpenSSL_add_all_algorithms();
      ]])
    ],[
      tst_openssl_add_all_algorithms_api="0x095"
    ])
  fi
  if test "$tst_openssl_add_all_algorithms_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        SSLeay_add_all_algorithms();
      ]])
    ],[
      tst_openssl_add_all_algorithms_api="0x091"
    ])
  fi
  case "$tst_openssl_add_all_algorithms_api" in
    0x097)
      tst_show="0.9.7"
      ;;
    0x095)
      tst_show="0.9.5"
      ;;
    0x091)
      tst_show="0.9.1"
      ;;
    *)
      tst_show="unknown"
      ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_openssl_add_all_algorithms_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_ADD_ALL_ALGORITHMS_API,
      $tst_openssl_add_all_algorithms_api,
      [OpenSSL link time API for OpenSSL_add_all_algorithms function. Configure
       script only definition. No matter what, do not ever define yourself.])
  fi
])


dnl CURL_CHECK_OPENSSL_DES_RANDOM_KEY_API
dnl -------------------------------------------------
dnl Link time verification check of which API is
dnl used for OpenSSL DES_random_key function.
dnl HAVE_OPENSSL_DES_RANDOM_KEY_API gets defined as
dnl apprpriate only for systems which actually run the
dnl configure script. Config files generated manually
dnl or in any other way shall not define this.

AC_DEFUN([CURL_CHECK_OPENSSL_DES_RANDOM_KEY_API], [
  #
  tst_openssl_des_random_key_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL DES_random_key API])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      if(0 != DES_random_key(0))
        return 1;
    ]])
  ],[
    tst_openssl_des_random_key_api="0x097"
  ])
  if test "$tst_openssl_des_random_key_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != des_random_key(0))
          return 1;
      ]])
    ],[
      tst_openssl_des_random_key_api="0x095"
    ])
  fi
  case "$tst_openssl_des_random_key_api" in
    0x097)
      tst_show="0.9.7"
      ;;
    0x095)
      tst_show="0.9.5"
      ;;
    *)
      tst_show="unknown"
      ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_openssl_des_random_key_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_DES_RANDOM_KEY_API,
      $tst_openssl_des_random_key_api,
      [OpenSSL link time API for OpenSSL DES_random_key function. Configure
       script only definition. No matter what, do not ever define yourself.])
  fi
])


dnl CURL_CHECK_OPENSSL_HEADERS_VERSION
dnl -------------------------------------------------
dnl Find out OpenSSL headers API version, as reported
dnl by OPENSSL_VERSION_NUMBER. No runtime checks
dnl allowed here for cross-compilation sake.

AC_DEFUN([CURL_CHECK_OPENSSL_HEADERS_VERSION], [
  #
  AC_MSG_CHECKING([for OpenSSL headers version])
  #
  tst_openssl_headers_api="unknown"
  #
  CURL_CHECK_DEF([OPENSSL_VERSION_NUMBER], [
#   ifdef USE_OPENSSL
#     include <openssl/crypto.h>
#   else
#     include <crypto.h>
#   endif
    ], [silent])
  if test "$curl_cv_have_def_OPENSSL_VERSION_NUMBER" = "yes"; then
    tst_openssl_headers_api=$curl_cv_def_OPENSSL_VERSION_NUMBER
  fi
  AC_MSG_RESULT([$tst_openssl_headers_api])
  #
])


dnl CURL_CHECK_OPENSSL_LIBRARY_VERSION
dnl -------------------------------------------------
dnl Find out OpenSSL library API version, performing
dnl only link tests in order to avoid getting fooled
dnl by mismatched OpenSSL headers. No runtime checks
dnl allowed here for cross-compilation sake.

AC_DEFUN([CURL_CHECK_OPENSSL_LIBRARY_VERSION], [
  #
  AC_MSG_CHECKING([for OpenSSL library version])
  #
  tst_openssl_library_api="unknown"
  #
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != OBJ_add_sigid(0, 0, 0))
          return 1;
      ]])
    ],[
      dnl 1.0.0 or newer
      tst_openssl_library_api="0x100"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != ERR_set_mark())
          return 1;
      ]])
    ],[
      dnl 0.9.8 or newer
      tst_openssl_library_api="0x098"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != ERR_peek_last_error())
          return 1;
      ]])
    ],[
      dnl 0.9.7 or newer
      tst_openssl_library_api="0x097"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != c2i_ASN1_OBJECT(0, 0, 0))
          return 1;
      ]])
    ],[
      dnl 0.9.6 or newer
      tst_openssl_library_api="0x096"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != SSL_CTX_set_purpose(0, 0))
          return 1;
      ]])
    ],[
      dnl 0.9.5 or newer
      tst_openssl_library_api="0x095"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != OBJ_obj2txt(0, 0, 0, 0))
          return 1;
      ]])
    ],[
      dnl 0.9.4 or newer
      tst_openssl_library_api="0x094"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != SSL_get_verify_depth(0))
          return 1;
      ]])
    ],[
      dnl 0.9.3 or newer
      tst_openssl_library_api="0x093"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != SSL_library_init())
          return 1;
      ]])
    ],[
      dnl 0.9.2 or newer
      tst_openssl_library_api="0x092"
    ])
  fi
  if test "$tst_openssl_library_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != SSL_CTX_set_cipher_list(0, 0))
          return 1;
      ]])
    ],[
      dnl 0.9.1 or newer
      tst_openssl_library_api="0x091"
    ])
  fi
  #
  case "$tst_openssl_library_api" in
    0x100)
      tst_show="1.0.0"
      ;;
    0x098)
      tst_show="0.9.8"
      ;;
    0x097)
      tst_show="0.9.7"
      ;;
    0x096)
      tst_show="0.9.6"
      ;;
    0x095)
      tst_show="0.9.5"
      ;;
    0x094)
      tst_show="0.9.4"
      ;;
    0x093)
      tst_show="0.9.3"
      ;;
    0x092)
      tst_show="0.9.2"
      ;;
    0x091)
      tst_show="0.9.1"
      ;;
    *)
      tst_show="unknown"
      ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
])
