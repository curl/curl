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
# serial 3


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
  tst_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL_add_all_algorithms API])
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([OPENSSL_add_all_algorithms_noconf])
    ],[
      tst_api="0x097"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([OpenSSL_add_all_algorithms])
    ],[
      tst_api="0x095"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSLeay_add_all_algorithms])
    ],[
      tst_api="0x091"
    ])
  fi
  case $tst_api in
    0x097) tst_show="0.9.7" ;;
    0x095) tst_show="0.9.5" ;;
    0x091) tst_show="0.9.1" ;;
    *)     tst_show="unknown" ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_ADD_ALL_ALGORITHMS_API, $tst_api,
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
  tst_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL DES_random_key API])
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([DES_random_key])
    ],[
      tst_api="0x097"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([des_random_key])
    ],[
      tst_api="0x095"
    ])
  fi
  case $tst_api in
    0x097) tst_show="0.9.7" ;;
    0x095) tst_show="0.9.5" ;;
    *)     tst_show="unknown" ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_DES_RANDOM_KEY_API, $tst_api,
      [OpenSSL link time API for OpenSSL DES_random_key function. Configure
       script only definition. No matter what, do not ever define yourself.])
  fi
])


dnl CURL_CHECK_OPENSSL_API_HEADERS
dnl -------------------------------------------------
dnl Find out OpenSSL headers API version, as reported
dnl by OPENSSL_VERSION_NUMBER. No runtime checks
dnl allowed here for cross-compilation support.
dnl HAVE_OPENSSL_API_HEADERS is defined as apprpriate
dnl only for systems which actually run the configure
dnl script. Config files generated manually or in any
dnl other way shall not define this.

AC_DEFUN([CURL_CHECK_OPENSSL_API_HEADERS], [
  #
  tst_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL headers version])
  CURL_CHECK_DEF([OPENSSL_VERSION_NUMBER], [
#   ifdef USE_OPENSSL
#     include <openssl/crypto.h>
#   else
#     include <crypto.h>
#   endif
    ], [silent])
  if test "$curl_cv_have_def_OPENSSL_VERSION_NUMBER" = "yes"; then
    tst_verlen=`expr "$curl_cv_def_OPENSSL_VERSION_NUMBER" : '.*'`
    case "x$tst_verlen" in
      x6)
        tst_vermaj=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 3`
        tst_vermin=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 4`
        tst_verfix=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 5`
        tst_api=0x$tst_vermaj$tst_vermin$tst_verfix
        ;;
      x11)
        tst_vermaj=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 3`
        tst_vermin=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 5`
        tst_verfix=`echo $curl_cv_def_OPENSSL_VERSION_NUMBER | cut -c 7`
        tst_api=0x$tst_vermaj$tst_vermin$tst_verfix
        ;;
      *)
        tst_api="unknown"
        ;;
    esac
    case $tst_api in
      0x110) tst_show="1.1.0" ;;
      0x101) tst_show="1.0.1" ;;
      0x100) tst_show="1.0.0" ;;
      0x099) tst_show="0.9.9" ;;
      0x098) tst_show="0.9.8" ;;
      0x097) tst_show="0.9.7" ;;
      0x096) tst_show="0.9.6" ;;
      0x095) tst_show="0.9.5" ;;
      0x094) tst_show="0.9.4" ;;
      0x093) tst_show="0.9.3" ;;
      0x092) tst_show="0.9.2" ;;
      0x091) tst_show="0.9.1" ;;
      *)     tst_show="unknown" ;;
    esac
    tst_show="$tst_show - $curl_cv_def_OPENSSL_VERSION_NUMBER"
  else
    tst_show="unknown"
  fi
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_API_HEADERS, $tst_api,
      [OpenSSL headers configure time API. Defined only by configure script.
       No matter what, do not ever define this manually or by any other means.])
  fi
  curl_openssl_api_headers=$tst_api
])


dnl CURL_CHECK_OPENSSL_API_LIBRARY
dnl -------------------------------------------------
dnl Find out OpenSSL library API version, performing
dnl only link tests in order to avoid getting fooled
dnl by mismatched OpenSSL headers. No runtime checks
dnl allowed here for cross-compilation support.
dnl HAVE_OPENSSL_API_LIBRARY is defined as apprpriate
dnl only for systems which actually run the configure
dnl script. Config files generated manually or in any
dnl other way shall not define this.
dnl
dnl Most probably we should not bother attempting to
dnl detect OpenSSL library development API versions
dnl 0.9.9 and 1.1.0. For our intended use, detecting
dnl released versions should be good enough.
dnl
dnl Given that currently we are not using the result
dnl of this check, except for informative purposes,
dnl lets try to figure out everything.

AC_DEFUN([CURL_CHECK_OPENSSL_API_LIBRARY], [
  #
  tst_api="unknown"
  #
  AC_MSG_CHECKING([for OpenSSL library version])
  if test "$tst_api" = "unknown"; then
    case $host in
      *-*-vms*)
        AC_LINK_IFELSE([
          AC_LANG_FUNC_LINK_TRY([SSL_CTX_set_not_resumbl_sess_cb])
        ],[
          tst_api="0x110"
        ])
        ;;
      *)
        AC_LINK_IFELSE([
          AC_LANG_FUNC_LINK_TRY([SSL_CTX_set_not_resumable_session_callback])
        ],[
          tst_api="0x110"
        ])
        ;;
    esac
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSL_renegotiate_abbreviated])
    ],[
      tst_api="0x101"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([OBJ_add_sigid])
    ],[
      tst_api="0x100"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([ERR_set_mark])
    ],[
      tst_api="0x098"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([ERR_peek_last_error])
    ],[
      tst_api="0x097"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([c2i_ASN1_OBJECT])
    ],[
      tst_api="0x096"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSL_CTX_set_purpose])
    ],[
      tst_api="0x095"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([OBJ_obj2txt])
    ],[
      tst_api="0x094"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSL_get_verify_depth])
    ],[
      tst_api="0x093"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSL_library_init])
    ],[
      tst_api="0x092"
    ])
  fi
  if test "$tst_api" = "unknown"; then
    AC_LINK_IFELSE([
      AC_LANG_FUNC_LINK_TRY([SSL_CTX_set_cipher_list])
    ],[
      tst_api="0x091"
    ])
  fi
  case $tst_api in
    0x110) tst_show="1.1.0" ;;
    0x101) tst_show="1.0.1" ;;
    0x100) tst_show="1.0.0" ;;
    0x099) tst_show="0.9.9" ;;
    0x098) tst_show="0.9.8" ;;
    0x097) tst_show="0.9.7" ;;
    0x096) tst_show="0.9.6" ;;
    0x095) tst_show="0.9.5" ;;
    0x094) tst_show="0.9.4" ;;
    0x093) tst_show="0.9.3" ;;
    0x092) tst_show="0.9.2" ;;
    0x091) tst_show="0.9.1" ;;
    *)     tst_show="unknown" ;;
  esac
  AC_MSG_RESULT([$tst_show])
  #
  if test "$tst_api" != "unknown"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_API_LIBRARY, $tst_api,
      [OpenSSL library link time API. Defined only by configure script.
       No matter what, do not ever define this manually or by any other means.])
  fi
  curl_openssl_api_library=$tst_api
])
