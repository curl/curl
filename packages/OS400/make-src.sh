#!/bin/sh
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
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
#
#       Command line interface tool compilation script for the OS/400.

SCRIPTDIR=$(dirname "${0}")
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/src" || exit 1


#       Check if built-in manual can be generated.

USE_MANUAL=
if [ -f "${IFSDIR}/docs/fetch.txt" ] && [ -n "${PASEPERL}" ]
then    "${PASEPERL}" ./mkhelp.pl < "${IFSDIR}/docs/fetch.txt" > tool_hugehelp.c
        USE_MANUAL="'USE_MANUAL'"
fi


#       Get source lists.
#       FETCH_CFILES are in the current directory.
#       FETCHX_CFILES are in the lib directory and need to be recompiled because
#               some function names change using macros.

get_make_vars Makefile.inc


#       Compile the sources into modules.

# shellcheck disable=SC2034
LINK=
MODULES=
# shellcheck disable=SC2034
INCLUDES="'${TOPDIR}/lib'"

for SRC in ${FETCHX_CFILES}
do      MODULE=$(db2_name "${SRC}")
        MODULE=$(db2_name "X${MODULE}")
        make_module "${MODULE}" "${SRC}" "${USE_MANUAL}"
done

for SRC in ${FETCH_CFILES}
do      MODULE=$(db2_name "${SRC}")
        make_module "${MODULE}" "${SRC}" "${USE_MANUAL}"
done


#       Link modules into program.

MODULES="$(echo "${MODULES}" | sed "s/[^ ][^ ]*/${TARGETLIB}\/&/g")"
CMD="CRTPGM PGM(${TARGETLIB}/${FETCHPGM})"
CMD="${CMD} ENTMOD(${TARGETLIB}/FETCHMAIN)"
CMD="${CMD} MODULE(${MODULES})"
CMD="${CMD} BNDSRVPGM(${TARGETLIB}/${SRVPGM} QADRTTS)"
CMD="${CMD} TGTRLS(${TGTRLS})"
CLcommand "${CMD}"


#       Create the IFS command.

IFSBIN="${IFSDIR}/bin"

if action_needed "${IFSBIN}"
then    mkdir -p "${IFSBIN}"
fi

rm -f "${IFSBIN}/fetch"
ln -s "/QSYS.LIB/${TARGETLIB}.LIB/${FETCHPGM}.PGM" "${IFSBIN}/fetch"


#       Create the CL interface program.

if action_needed "${LIBIFSNAME}/FETCHCL.PGM" "${SCRIPTDIR}/fetchcl.c"
then    CMD="CRTBNDC PGM(${TARGETLIB}/${FETCHCLI})"
        CMD="${CMD} SRCSTMF('${SCRIPTDIR}/fetchcl.c')"
        CMD="${CMD} DEFINE('FETCHPGM=\"${FETCHPGM}\"')"
        CMD="${CMD} TGTCCSID(${TGTCCSID})"
        CLcommand "${CMD}"
fi


#       Create the CL command.

if action_needed "${LIBIFSNAME}/${FETCHCMD}.CMD" "${SCRIPTDIR}/fetch.cmd"
then    CMD="CRTCMD CMD(${TARGETLIB}/${FETCHCMD}) PGM(${TARGETLIB}/${FETCHCLI})"
        CMD="${CMD} SRCSTMF('${SCRIPTDIR}/fetch.cmd')"
        CLcommand "${CMD}"
fi
