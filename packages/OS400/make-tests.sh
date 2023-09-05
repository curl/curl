#!/bin/sh
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
###########################################################################
#
#       tests compilation script for the OS/400.
#


SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/tests"


#       Build programs in a directory.

build_all_programs()

{
        #       Compile all programs.
        #       The list is found in variable "noinst_PROGRAMS"

        INCLUDES="'`pwd`' '${TOPDIR}/lib' '${TOPDIR}/src'"
        MODS="${1}"
        SRVPGMS="${2}"

        for PGM in ${noinst_PROGRAMS}
        do      DB2PGM=`db2_name "${PGM}"`
                PGMIFSNAME="${LIBIFSNAME}/${DB2PGM}.PGM"

                #       Extract preprocessor symbol definitions from
                #               compilation options for the program.

                PGMCFLAGS="`eval echo \"\\${${PGM}_CFLAGS}\"`"
                PGMDFNS=

                for FLAG in ${PGMCFLAGS}
                do      case "${FLAG}" in
                        -D?*)   DEFINE="`echo \"${FLAG}\" | sed 's/^..//'`"
                                PGMDFNS="${PGMDFNS} '${DEFINE}'"
                                ;;
                        esac
                done

                #        Compile all C sources for the program into modules.

                PGMSOURCES="`eval echo \"\\${${PGM}_SOURCES}\"`"
                LINK=
                MODULES=

                for SOURCE in ${PGMSOURCES}
                do      case "${SOURCE}" in
                        *.c)    #       Special processing for libxxx.c files:
                                #               their module name is determined
                                #               by the target PROGRAM name.

                                case "${SOURCE}" in
                                lib*.c) MODULE="${DB2PGM}"
                                        ;;
                                *)      MODULE=`db2_name "${SOURCE}"`
                                        ;;
                                esac

                                #       If source is in a sibling directory,
                                #               prefix module name with 'X'.

                                case "${SOURCE}" in
                                ../*)   MODULE=`db2_name "X${MODULE}"`
                                            ;;
                                esac

                                make_module "${MODULE}" "${SOURCE}" "${PGMDFNS}"
                                if action_needed "${PGMIFSNAME}" "${MODIFSNAME}"
                                then    LINK=yes
                                fi
                                ;;
                        esac
                done

                #       Link program if needed.

                if [ "${LINK}" ]
                then    PGMLDADD="`eval echo \"\\${${PGM}_LDADD}\"`"
                        for ARG in ${PGMLDADD}
                        do      case "${ARG}" in
                                -*)     ;;              # Ignore non-module.
                                *)      MODULES="${MODULES} "`db2_name "${ARG}"`
                                        ;;
                                esac
                        done
                        MODULES="`echo \"${MODULES}\" |
                            sed \"s/[^ ][^ ]*/${TARGETLIB}\/&/g\"`"
                        CMD="CRTPGM PGM(${TARGETLIB}/${DB2PGM})"
                        CMD="${CMD} ENTMOD(${TARGETLIB}/CURLMAIN)"
                        CMD="${CMD} MODULE(${MODULES} ${MODS})"
                        CMD="${CMD} BNDSRVPGM(${SRVPGMS} QADRTTS)"
                        CMD="${CMD} TGTRLS(${TGTRLS})"
                        CLcommand "${CMD}"
                fi
        done
}


#       Build programs in the server directory.

(
        cd server
        get_make_vars Makefile.inc
        build_all_programs "${TARGETLIB}/OS400SYS"
)


#       Build all programs in the libtest subdirectory.

(
        cd libtest
        get_make_vars Makefile.inc

        #       Special case: redefine chkhostname compilation parameters.

        chkhostname_SOURCES=chkhostname.c
        chkhostname_LDADD=curl_gethostname.o

        build_all_programs "" "${TARGETLIB}/${SRVPGM}"
)
