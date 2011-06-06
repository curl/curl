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
# serial 1


dnl CURL_CHECK_OPENSSL_ADD_ALL_API
dnl -------------------------------------------------
dnl Link time verification check of which API is
dnl used for for the *_add_all_algorithms function.

AC_DEFUN([CURL_CHECK_OPENSSL_ADD_ALL_API], [
  #
  tst_links_add_all_api_091="unknown"
  tst_links_add_all_api_095="unknown"
  tst_links_add_all_api_097="unknown"
  #
  AC_MSG_CHECKING([if OpenSSL *_add_all_algorithms API is 0.9.1])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      SSLeay_add_all_algorithms();
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_add_all_api_091="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_add_all_api_091="no"
  ])
  if test "$tst_links_add_all_api_091" != "yes"; then
    AC_MSG_CHECKING([if OpenSSL *_add_all_algorithms API is 0.9.5])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        OpenSSL_add_all_algorithms();
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_links_add_all_api_095="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_links_add_all_api_095="no"
    ])
  fi
  if test "$tst_links_add_all_api_091" != "yes" &&
     test "$tst_links_add_all_api_095" != "yes"; then
    AC_MSG_CHECKING([if OpenSSL *_add_all_algorithms API is 0.9.7])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        OPENSSL_add_all_algorithms_conf();
        OPENSSL_add_all_algorithms_noconf();
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_links_add_all_api_097="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_links_add_all_api_097="no"
    ])
  fi
  #
  if test "$tst_links_add_all_api_091" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_ADD_ALL_API_091, 1,
      [Define to 1 if OpenSSL *_add_all_algorithms API is 0.9.1])
  elif test "$tst_links_add_all_api_095" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_ADD_ALL_API_095, 1,
      [Define to 1 if OpenSSL *_add_all_algorithms API is 0.9.5])
  elif test "$tst_links_add_all_api_097" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_ADD_ALL_API_097, 1,
      [Define to 1 if OpenSSL *_add_all_algorithms API is 0.9.7])
  fi
])


dnl CURL_CHECK_OPENSSL_DESRANDKEY_API
dnl -------------------------------------------------
dnl Verify if DES_random_key or des_random_key can be
dnl linked. When true, define HAVE_DES_RANDOM_KEY_097
dnl or HAVE_DES_RANDOM_KEY_LOWER.

AC_DEFUN([CURL_CHECK_OPENSSL_DESRANDKEY_API], [
  #
  tst_links_des_random_key_api_097="unknown"
  tst_links_des_random_key_api_095="unknown"
  #
  AC_MSG_CHECKING([if OpenSSL des_random_key API is 0.9.7])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
    ]],[[
      if(0 != DES_random_key(0))
        return 1;
    ]])
  ],[
    AC_MSG_RESULT([yes])
    tst_links_des_random_key_api_097="yes"
  ],[
    AC_MSG_RESULT([no])
    tst_links_des_random_key_api_097="no"
  ])
  if test "$tst_links_des_random_key_api_097" != "yes"; then
    AC_MSG_CHECKING([if OpenSSL des_random_key API is 0.9.5])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
      ]],[[
        if(0 != des_random_key(0))
          return 1;
      ]])
    ],[
      AC_MSG_RESULT([yes])
      tst_links_des_random_key_api_095="yes"
    ],[
      AC_MSG_RESULT([no])
      tst_links_des_random_key_api_095="no"
    ])
  fi
  #
  if test "$tst_links_des_random_key_api_097" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_DESRANDKEY_API_097, 1,
      [Define to 1 if OpenSSL des_random_key API is 0.9.7])
  elif test "$tst_links_des_random_key_api_095" = "yes"; then
    AC_DEFINE_UNQUOTED(HAVE_OPENSSL_DESRANDKEY_API_095, 1,
      [Define to 1 if OpenSSL des_random_key API is 0.9.5])
  fi
])
