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

AC_DEFUN([CURL_WITH_MESALINK], [
dnl ----------------------------------------------------
dnl check for MesaLink
dnl ----------------------------------------------------

if test "x$OPT_MESALINK" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  ssl_msg=

  if test X"$OPT_MESALINK" != Xno; then

    if test "$OPT_MESALINK" = "yes"; then
      OPT_MESALINK=""
    fi

    if test -z "$OPT_MESALINK" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(mesalink, mesalink_library_init,
      dnl libmesalink found, set the variable
       [
         AC_DEFINE(USE_MESALINK, 1, [if MesaLink is enabled])
         AC_SUBST(USE_MESALINK, [1])
         MESALINK_ENABLED=1
         USE_MESALINK="yes"
         ssl_msg="MesaLink"
	 test mesalink != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ])
    fi

    addld=""
    addlib=""
    addcflags=""
    mesalinklib=""

    if test "x$USE_MESALINK" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_MESALINK/lib$libsuff
      addcflags=-I$OPT_MESALINK/include
      mesalinklib=$OPT_MESALINK/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(mesalink, mesalink_library_init,
       [
       AC_DEFINE(USE_MESALINK, 1, [if MesaLink is enabled])
       AC_SUBST(USE_MESALINK, [1])
       MESALINK_ENABLED=1
       USE_MESALINK="yes"
       ssl_msg="MesaLink"
       test mesalink != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       [
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
       ])
    fi

    if test "x$USE_MESALINK" = "xyes"; then
      AC_MSG_NOTICE([detected MesaLink])

      LIBS="-lmesalink $LIBS"

      if test -n "$mesalinklib"; then
        dnl when shared libs were found in a path that the run-time
        dnl linker doesn't search through, we need to add it to
        dnl LD_LIBRARY_PATH to prevent further configure tests to fail
        dnl due to this
        if test "x$cross_compiling" != "xyes"; then
          LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$mesalinklib"
          export LD_LIBRARY_PATH
          AC_MSG_NOTICE([Added $mesalinklib to LD_LIBRARY_PATH])
        fi
      fi
    fi

  fi dnl MesaLink not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi
])
