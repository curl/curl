#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) David Shaw <dshaw@jabberwocky.com>
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
# SPDX-License-Identifier: fetch
#
###########################################################################
# LIBFETCH_CHECK_CONFIG ([DEFAULT-ACTION], [MINIMUM-VERSION],
#                       [ACTION-IF-YES], [ACTION-IF-NO])
# ----------------------------------------------------------
#      David Shaw <dshaw@jabberwocky.com>   May-09-2006
#
# Checks for libfetch.  DEFAULT-ACTION is the string yes or no to
# specify whether to default to --with-libfetch or --without-libfetch.
# If not supplied, DEFAULT-ACTION is yes.  MINIMUM-VERSION is the
# minimum version of libfetch to accept.  Pass the version as a regular
# version number like 7.10.1. If not supplied, any version is
# accepted.  ACTION-IF-YES is a list of shell commands to run if
# libfetch was successfully found and passed the various tests.
# ACTION-IF-NO is a list of shell commands that are run otherwise.
# Note that using --without-libfetch does run ACTION-IF-NO.
#
# This macro #defines HAVE_LIBFETCH if a working libfetch setup is
# found, and sets @LIBFETCH@ and @LIBFETCH_CPPFLAGS@ to the necessary
# values.  Other useful defines are LIBFETCH_FEATURE_xxx where xxx are
# the various features supported by libfetch, and LIBFETCH_PROTOCOL_yyy
# where yyy are the various protocols supported by libfetch.  Both xxx
# and yyy are capitalized.  See the list of AH_TEMPLATEs at the top of
# the macro for the complete list of possible defines.  Shell
# variables $libfetch_feature_xxx and $libfetch_protocol_yyy are also
# defined to 'yes' for those features and protocols that were found.
# Note that xxx and yyy keep the same capitalization as in the
# fetch-config list (e.g. it's "HTTP" and not "http").
#
# Users may override the detected values by doing something like:
# LIBFETCH="-lfetch" LIBFETCH_CPPFLAGS="-I/usr/myinclude" ./configure
#
# For the sake of sanity, this macro assumes that any libfetch that is found is
# after version 7.7.2, the first version that included the fetch-config script.
# Note that it is important for people packaging binary versions of libfetch to
# include this script!  Without fetch-config, we can only guess what protocols
# are available, or use fetch_version_info to figure it out at runtime.

AC_DEFUN([LIBFETCH_CHECK_CONFIG],
[
  AH_TEMPLATE([LIBFETCH_FEATURE_SSL],[Defined if libfetch supports SSL])
  AH_TEMPLATE([LIBFETCH_FEATURE_KRB4],[Defined if libfetch supports KRB4])
  AH_TEMPLATE([LIBFETCH_FEATURE_IPV6],[Defined if libfetch supports IPv6])
  AH_TEMPLATE([LIBFETCH_FEATURE_LIBZ],[Defined if libfetch supports libz])
  AH_TEMPLATE([LIBFETCH_FEATURE_ASYNCHDNS],[Defined if libfetch supports AsynchDNS])
  AH_TEMPLATE([LIBFETCH_FEATURE_IDN],[Defined if libfetch supports IDN])
  AH_TEMPLATE([LIBFETCH_FEATURE_SSPI],[Defined if libfetch supports SSPI])
  AH_TEMPLATE([LIBFETCH_FEATURE_NTLM],[Defined if libfetch supports NTLM])

  AH_TEMPLATE([LIBFETCH_PROTOCOL_HTTP],[Defined if libfetch supports HTTP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_HTTPS],[Defined if libfetch supports HTTPS])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_FTP],[Defined if libfetch supports FTP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_FTPS],[Defined if libfetch supports FTPS])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_FILE],[Defined if libfetch supports FILE])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_TELNET],[Defined if libfetch supports TELNET])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_LDAP],[Defined if libfetch supports LDAP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_DICT],[Defined if libfetch supports DICT])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_TFTP],[Defined if libfetch supports TFTP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_RTSP],[Defined if libfetch supports RTSP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_POP3],[Defined if libfetch supports POP3])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_IMAP],[Defined if libfetch supports IMAP])
  AH_TEMPLATE([LIBFETCH_PROTOCOL_SMTP],[Defined if libfetch supports SMTP])

  AC_ARG_WITH(libfetch,
     AS_HELP_STRING([--with-libfetch=PREFIX],[look for the fetch library in PREFIX/lib and headers in PREFIX/include]),
     [_libfetch_with=$withval],[_libfetch_with=ifelse([$1],,[yes],[$1])])

  if test "$_libfetch_with" != "no" ; then

     AC_PROG_AWK

     _libfetch_version_parse="eval $AWK '{split(\$NF,A,\".\"); X=256*256*A[[1]]+256*A[[2]]+A[[3]]; print X;}'"

     _libfetch_try_link=yes

     if test -d "$_libfetch_with" ; then
        LIBFETCH_CPPFLAGS="-I$withval/include"
        _libfetch_ldflags="-L$withval/lib"
        AC_PATH_PROG([_libfetch_config],[fetch-config],[],
                     ["$withval/bin"])
     else
        AC_PATH_PROG([_libfetch_config],[fetch-config],[],[$PATH])
     fi

     if test x$_libfetch_config != "x" ; then
        AC_CACHE_CHECK([for the version of libfetch],
           [libfetch_cv_lib_fetch_version],
           [libfetch_cv_lib_fetch_version=`$_libfetch_config --version | $AWK '{print $[]2}'`])

        _libfetch_version=`echo $libfetch_cv_lib_fetch_version | $_libfetch_version_parse`
        _libfetch_wanted=`echo ifelse([$2],,[0],[$2]) | $_libfetch_version_parse`

        if test $_libfetch_wanted -gt 0 ; then
           AC_CACHE_CHECK([for libfetch >= version $2],
              [libfetch_cv_lib_version_ok],
              [
              if test $_libfetch_version -ge $_libfetch_wanted ; then
                 libfetch_cv_lib_version_ok=yes
              else
                 libfetch_cv_lib_version_ok=no
              fi
              ])
        fi

        if test $_libfetch_wanted -eq 0 || test x$libfetch_cv_lib_version_ok = xyes ; then
           if test x"$LIBFETCH_CPPFLAGS" = "x" ; then
              LIBFETCH_CPPFLAGS=`$_libfetch_config --cflags`
           fi
           if test x"$LIBFETCH" = "x" ; then
              LIBFETCH=`$_libfetch_config --libs`

              # This is so silly, but Apple actually has a bug in their
              # fetch-config script.  Fixed in Tiger, but there are still
              # lots of Panther installs around.
              case "${host}" in
                 powerpc-apple-darwin7*)
                    LIBFETCH=`echo $LIBFETCH | sed -e 's|-arch i386||g'`
                 ;;
              esac
           fi

           # All fetch-config scripts support --feature
           _libfetch_features=`$_libfetch_config --feature`

           # Is it modern enough to have --protocols? (7.12.4)
           if test $_libfetch_version -ge 461828 ; then
              _libfetch_protocols=`$_libfetch_config --protocols`
           fi
        else
           _libfetch_try_link=no
        fi

        unset _libfetch_wanted
     fi

     if test $_libfetch_try_link = yes ; then

        # we did not find fetch-config, so let's see if the user-supplied
        # link line (or failing that, "-lfetch") is enough.
        LIBFETCH=${LIBFETCH-"$_libfetch_ldflags -lfetch"}

        AC_CACHE_CHECK([whether libfetch is usable],
           [libfetch_cv_lib_fetch_usable],
           [
           _libfetch_save_cppflags=$CPPFLAGS
           CPPFLAGS="$LIBFETCH_CPPFLAGS $CPPFLAGS"
           _libfetch_save_libs=$LIBS
           LIBS="$LIBFETCH $LIBS"

           AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <fetch/fetch.h>]],[[
/* Try to use a few common options to force a failure if we are
   missing symbols or cannot link. */
int x;
fetch_easy_setopt(NULL,FETCHOPT_URL,NULL);
x=FETCH_ERROR_SIZE;
x=FETCHOPT_WRITEFUNCTION;
x=FETCHOPT_WRITEDATA;
x=FETCHOPT_ERRORBUFFER;
x=FETCHOPT_STDERR;
x=FETCHOPT_VERBOSE;
if (x) {;}
]])],libfetch_cv_lib_fetch_usable=yes,libfetch_cv_lib_fetch_usable=no)

           CPPFLAGS=$_libfetch_save_cppflags
           LIBS=$_libfetch_save_libs
           unset _libfetch_save_cppflags
           unset _libfetch_save_libs
           ])

        if test $libfetch_cv_lib_fetch_usable = yes ; then

           # Does fetch_free() exist in this version of libfetch?
           # If not, fake it with free()

           _libfetch_save_cppflags=$CPPFLAGS
           CPPFLAGS="$CPPFLAGS $LIBFETCH_CPPFLAGS"
           _libfetch_save_libs=$LIBS
           LIBS="$LIBS $LIBFETCH"

           AC_CHECK_DECL([fetch_free],[],
              [AC_DEFINE([fetch_free],[free],
                [Define fetch_free() as free() if our version of fetch lacks fetch_free.])],
              [[#include <fetch/fetch.h>]])

           CPPFLAGS=$_libfetch_save_cppflags
           LIBS=$_libfetch_save_libs
           unset _libfetch_save_cppflags
           unset _libfetch_save_libs

           AC_DEFINE(HAVE_LIBFETCH,1,
             [Define to 1 if you have a functional fetch library.])
           AC_SUBST(LIBFETCH_CPPFLAGS)
           AC_SUBST(LIBFETCH)

           for _libfetch_feature in $_libfetch_features ; do
              AC_DEFINE_UNQUOTED(AS_TR_CPP(libfetch_feature_$_libfetch_feature),[1])
              eval AS_TR_SH(libfetch_feature_$_libfetch_feature)=yes
           done

           if test "x$_libfetch_protocols" = "x" ; then

              # We do not have --protocols, so just assume that all
              # protocols are available
              _libfetch_protocols="HTTP FTP FILE TELNET LDAP DICT TFTP"

              if test x$libfetch_feature_SSL = xyes ; then
                 _libfetch_protocols="$_libfetch_protocols HTTPS"

                 # FTPS was not standards-compliant until version
                 # 7.11.0 (0x070b00 == 461568)
                 if test $_libfetch_version -ge 461568; then
                    _libfetch_protocols="$_libfetch_protocols FTPS"
                 fi
              fi

              # RTSP, IMAP, POP3 and SMTP were added in
              # 7.20.0 (0x071400 == 463872)
              if test $_libfetch_version -ge 463872; then
                 _libfetch_protocols="$_libfetch_protocols RTSP IMAP POP3 SMTP"
              fi
           fi

           for _libfetch_protocol in $_libfetch_protocols ; do
              AC_DEFINE_UNQUOTED(AS_TR_CPP(libfetch_protocol_$_libfetch_protocol),[1])
              eval AS_TR_SH(libfetch_protocol_$_libfetch_protocol)=yes
           done
        else
           unset LIBFETCH
           unset LIBFETCH_CPPFLAGS
        fi
     fi

     unset _libfetch_try_link
     unset _libfetch_version_parse
     unset _libfetch_config
     unset _libfetch_feature
     unset _libfetch_features
     unset _libfetch_protocol
     unset _libfetch_protocols
     unset _libfetch_version
     unset _libfetch_ldflags
  fi

  if test x$_libfetch_with = xno || test x$libfetch_cv_lib_fetch_usable != xyes ; then
     # This is the IF-NO path
     ifelse([$4],,:,[$4])
  else
     # This is the IF-YES path
     ifelse([$3],,:,[$3])
  fi

  unset _libfetch_with
])
