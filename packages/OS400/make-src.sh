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
#       Command line interface tool compilation script for the OS/400.

SCRIPTDIR=$(dirname "${0}")
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/src" || exit 1


#       Check if built-in manual can be generated.

USE_MANUAL=
if [ -f "${IFSDIR}/docs/curl.txt" ] && [ -n "${PASEPERL}" ]
then    "${PASEPERL}" ./mkhelp.pl < "${IFSDIR}/docs/curl.txt" > tool_hugehelp.c
        USE_MANUAL="'USE_MANUAL'"
fi


#       Get source lists.
#       CURL_CFILES are in the current directory.
#       CURLX_CFILES are in the lib directory and need to be recompiled because
#               some function names change using macros.

get_make_vars Makefile.inc


#       Add hugehelp, as it is not included in Makefile.inc.
if [ "${USE_MANUAL}" = "'USE_MANUAL'" ]
then
        CURL_CFILES="${CURL_CFILES} tool_hugehelp.c"
        CURL_HFILES="${CURL_HFILES} tool_hugehelp.h"
fi

#       Compile the sources into modules.

# shellcheck disable=SC2034
LINK=
MODULES=
# shellcheck disable=SC2034
INCLUDES="'${TOPDIR}/lib'"

# shellcheck disable=SC2153
for SRC in ${CURLX_CFILES}
do      MODULE=$(db2_name "${SRC}")
        MODULE=$(db2_name "X${MODULE}")
        make_module "${MODULE}" "${SRC}" "${USE_MANUAL}"
done

for SRC in ${CURL_CFILES}
do      MODULE=$(db2_name "${SRC}")
        make_module "${MODULE}" "${SRC}" "${USE_MANUAL}"
done


#       Link modules into program.

MODULES="$(echo "${MODULES}" | sed "s/[^ ][^ ]*/${TARGETLIB}\/&/g")"
CMD="CRTPGM PGM(${TARGETLIB}/${CURLPGM})"
CMD="${CMD} ENTMOD(${TARGETLIB}/CURLMAIN)"
CMD="${CMD} MODULE(${MODULES})"
CMD="${CMD} BNDSRVPGM(${TARGETLIB}/${SRVPGM} QADRTTS)"
CMD="${CMD} TGTRLS(${TGTRLS})"
CLcommand "${CMD}"


#       Create the IFS command.

IFSBIN="${IFSDIR}/bin"

if action_needed "${IFSBIN}"
then    mkdir -p "${IFSBIN}"
fi

rm -f "${IFSBIN}/curl"
ln -s "/QSYS.LIB/${TARGETLIB}.LIB/${CURLPGM}.PGM" "${IFSBIN}/curl"


#       Create the CL interface program.

if action_needed "${LIBIFSNAME}/CURLCL.PGM" "${SCRIPTDIR}/curlcl.c"
then    CMD="CRTBNDC PGM(${TARGETLIB}/${CURLCLI})"
        CMD="${CMD} SRCSTMF('${SCRIPTDIR}/curlcl.c')"
        CMD="${CMD} DEFINE('CURLPGM=\"${CURLPGM}\"')"
        CMD="${CMD} TGTCCSID(${TGTCCSID})"
        CLcommand "${CMD}"
fi


#       Create the CL command.

if action_needed "${LIBIFSNAME}/${CURLCMD}.CMD" "${SCRIPTDIR}/curl.cmd"
then    CMD="CRTCMD CMD(${TARGETLIB}/${CURLCMD}) PGM(${TARGETLIB}/${CURLCLI})"
        CMD="${CMD} SRCSTMF('${SCRIPTDIR}/curl.cmd')"
        CLcommand "${CMD}"
fi
