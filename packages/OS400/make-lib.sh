#!/bin/sh
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
###########################################################################
#
#       libcurl compilation script for the OS/400.
#

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/lib"

#       Need to have IFS access to the mih/cipher header file.

if action_needed cipher.mih '/QSYS.LIB/QSYSINC.LIB/MIH.FILE/CIPHER.MBR'
then    rm -f cipher.mih
        ln -s '/QSYS.LIB/QSYSINC.LIB/MIH.FILE/CIPHER.MBR' cipher.mih
fi


#      Create and compile the identification source file.

echo '#pragma comment(user, "libcurl version '"${LIBCURL_VERSION}"'")' > os400.c
echo '#pragma comment(user, __DATE__)' >> os400.c
echo '#pragma comment(user, __TIME__)' >> os400.c
echo '#pragma comment(copyright, "Copyright (C) 1998-2016 Daniel Stenberg et al. OS/400 version by P. Monnerat")' >> os400.c
make_module     OS400           os400.c
LINK=                           # No need to rebuild service program yet.
MODULES=


#       Get source list.

sed -e ':begin'                                                         \
    -e '/\\$/{'                                                         \
    -e 's/\\$/ /'                                                       \
    -e 'N'                                                              \
    -e 'bbegin'                                                         \
    -e '}'                                                              \
    -e 's/\n//g'                                                        \
    -e 's/[[:space:]]*$//'                                              \
    -e 's/^\([A-Za-z][A-Za-z0-9_]*\)[[:space:]]*=[[:space:]]*\(.*\)/\1="\2"/' \
    -e 's/\$(\([A-Za-z][A-Za-z0-9_]*\))/${\1}/g'                        \
        < Makefile.inc > tmpscript.sh
. ./tmpscript.sh


#       Compile the sources into modules.

INCLUDES="'`pwd`'"

# Create a small C program to check ccsidcurl.c is up to date
if action_needed "${LIBIFSNAME}/CHKSTRINGS.PGM"
then
  CMD="CRTBNDC PGM(${TARGETLIB}/CHKSTRINGS) SRCSTMF('${SCRIPTDIR}/chkstrings.c')"
  CMD="${CMD} INCDIR('${TOPDIR}/include/curl' '${TOPDIR}/include' '${SRCDIR}' ${INCLUDES})"
  system -i "${CMD}"
  if [ $? -ne 0 ]
  then
    echo "ERROR: Failed to build CHKSTRINGS *PGM object!"
    exit 2
  else
    ${LIBIFSNAME}/CHKSTRINGS.PGM
    if [ $? -ne 0 ]
    then
      echo "ERROR: CHKSTRINGS failed!"
      exit 2
    fi
  fi
fi

make_module     OS400SYS        "${SCRIPTDIR}/os400sys.c"
make_module     CCSIDCURL       "${SCRIPTDIR}/ccsidcurl.c"

for SRC in ${CSOURCES}
do      MODULE=`db2_name "${SRC}"`
        make_module "${MODULE}" "${SRC}"
done


#       If needed, (re)create the static binding directory.

if action_needed "${LIBIFSNAME}/${STATBNDDIR}.BNDDIR"
then    LINK=YES
fi

if [ "${LINK}" ]
then    rm -rf "${LIBIFSNAME}/${STATBNDDIR}.BNDDIR"
        CMD="CRTBNDDIR BNDDIR(${TARGETLIB}/${STATBNDDIR})"
        CMD="${CMD} TEXT('LibCurl API static binding directory')"
        system "${CMD}"

        for MODULE in ${MODULES}
        do      CMD="ADDBNDDIRE BNDDIR(${TARGETLIB}/${STATBNDDIR})"
                CMD="${CMD} OBJ((${TARGETLIB}/${MODULE} *MODULE))"
                system "${CMD}"
        done
fi


#       The exportation file for service program creation must be in a DB2
#               source file, so make sure it exists.

if action_needed "${LIBIFSNAME}/TOOLS.FILE"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/TOOLS) RCDLEN(112)"
        CMD="${CMD} TEXT('curl: build tools')"
        system "${CMD}"
fi


#       Gather the list of symbols to export.

EXPORTS=`grep '^CURL_EXTERN[[:space:]]'                                 \
              "${TOPDIR}"/include/curl/*.h                              \
              "${SCRIPTDIR}/ccsidcurl.h"                                |
         sed -e 's/^.*CURL_EXTERN[[:space:]]\(.*\)(.*$/\1/'             \
             -e 's/[[:space:]]*$//'                                     \
             -e 's/^.*[[:space:]][[:space:]]*//'                        \
             -e 's/^\*//'                                               \
             -e 's/(\(.*\))/\1/'`

#       Create the service program exportation file in DB2 member if needed.

BSF="${LIBIFSNAME}/TOOLS.FILE/BNDSRC.MBR"

if action_needed "${BSF}" Makefile.am
then    LINK=YES
fi

if [ "${LINK}" ]
then    echo " STRPGMEXP PGMLVL(*CURRENT) SIGNATURE('LIBCURL_${SONAME}')" \
            > "${BSF}"
        for EXPORT in ${EXPORTS}
        do      echo ' EXPORT    SYMBOL("'"${EXPORT}"'")' >> "${BSF}"
        done

        echo ' ENDPGMEXP' >> "${BSF}"
fi


#       Build the service program if needed.

if action_needed "${LIBIFSNAME}/${SRVPGM}.SRVPGM"
then    LINK=YES
fi

if [ "${LINK}" ]
then    CMD="CRTSRVPGM SRVPGM(${TARGETLIB}/${SRVPGM})"
        CMD="${CMD} SRCFILE(${TARGETLIB}/TOOLS) SRCMBR(BNDSRC)"
        CMD="${CMD} MODULE(${TARGETLIB}/OS400)"
        CMD="${CMD} BNDDIR(${TARGETLIB}/${STATBNDDIR}"
        if [ "${WITH_ZLIB}" != 0 ]
        then    CMD="${CMD} ${ZLIB_LIB}/${ZLIB_BNDDIR}"
                liblist -a "${ZLIB_LIB}"
        fi
        if [ "${WITH_LIBSSH2}" != 0 ]
        then    CMD="${CMD} ${LIBSSH2_LIB}/${LIBSSH2_BNDDIR}"
                liblist -a "${LIBSSH2_LIB}"
        fi
        CMD="${CMD})"
        CMD="${CMD} BNDSRVPGM(QADRTTS QGLDCLNT QGLDBRDR)"
        CMD="${CMD} TEXT('curl API library')"
        CMD="${CMD} TGTRLS(${TGTRLS})"
        system "${CMD}"
        LINK=YES
fi


#       If needed, (re)create the dynamic binding directory.

if action_needed "${LIBIFSNAME}/${DYNBNDDIR}.BNDDIR"
then    LINK=YES
fi

if [ "${LINK}" ]
then    rm -rf "${LIBIFSNAME}/${DYNBNDDIR}.BNDDIR"
        CMD="CRTBNDDIR BNDDIR(${TARGETLIB}/${DYNBNDDIR})"
        CMD="${CMD} TEXT('LibCurl API dynamic binding directory')"
        system "${CMD}"
        CMD="ADDBNDDIRE BNDDIR(${TARGETLIB}/${DYNBNDDIR})"
        CMD="${CMD} OBJ((*LIBL/${SRVPGM} *SRVPGM))"
        system "${CMD}"
fi


#       Rebuild the formdata test if needed.

if [ "${TEST_FORMDATA}" ]
then    MODULES=
        make_module TFORMDATA   formdata.c      "'_FORM_DEBUG' 'CURLDEBUG'"
        make_module TSTREQUAL   strequal.c      "'_FORM_DEBUG' 'CURLDEBUG'"
        make_module TMEMDEBUG   memdebug.c      "'_FORM_DEBUG' 'CURLDEBUG'"
        make_module TMPRINTF    mprintf.c       "'_FORM_DEBUG' 'CURLDEBUG'"
        make_module TSTRERROR   strerror.c      "'_FORM_DEBUG' 'CURLDEBUG'"
        #       The following modules should not be needed (see comment in
        #               formdata.c. However, there are some unsatisfied
        #               external references leading in the following
        #               modules to be (recursively) needed.
        MODULES="${MODULES} EASY STRDUP SSLGEN GSKIT HOSTIP HOSTIP4 HOSTIP6"
        MODULES="${MODULES} URL HASH TRANSFER GETINFO COOKIE SENDF SELECT"
        MODULES="${MODULES} INET_NTOP SHARE HOSTTHRE MULTI LLIST FTP HTTP"
        MODULES="${MODULES} HTTP_DIGES HTTP_CHUNK HTTP_NEGOT TIMEVAL HOSTSYN"
        MODULES="${MODULES} CONNECT SOCKS PROGRESS ESCAPE INET_PTON GETENV"
        MODULES="${MODULES} DICT LDAP TELNET FILE TFTP NETRC PARSEDATE"
        MODULES="${MODULES} SPEEDCHECK SPLAY BASE64 SECURITY IF2IP MD5"
        MODULES="${MODULES} KRB5 OS400SYS"

        PGMIFSNAME="${LIBIFSNAME}/TFORMDATA.PGM"

        if action_needed "${PGMIFSNAME}"
        then    LINK=YES
        fi

        if [ "${LINK}" ]
        then    CMD="CRTPGM PGM(${TARGETLIB}/TFORMDATA)"
                CMD="${CMD} ENTMOD(QADRT/QADRTMAIN2)"
                CMD="${CMD} MODULE("

                for MODULE in ${MODULES}
                do      CMD="${CMD} ${TARGETLIB}/${MODULE}"
                done

                CMD="${CMD} ) BNDSRVPGM(QADRTTS)"
                CMD="${CMD} TGTRLS(${TGTRLS})"
                system "${CMD}"
        fi
fi
