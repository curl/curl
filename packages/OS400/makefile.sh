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
#       curl compilation script for the OS/400.
#
#
#       This is a shell script since make is not a standard component of OS/400.

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}"


#       Create the OS/400 library if it does not exist.

if action_needed "${LIBIFSNAME}"
then    CMD="CRTLIB LIB(${TARGETLIB}) TEXT('curl: multiprotocol support API')"
        CLcommand "${CMD}"
fi


#       Create the DOCS source file if it does not exist.

if action_needed "${LIBIFSNAME}/DOCS.FILE"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/DOCS) RCDLEN(240)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('Documentation texts')"
        CLcommand "${CMD}"
fi


#       Copy some documentation files if needed.

for TEXT in "${TOPDIR}/COPYING" "${SCRIPTDIR}/README.OS400"             \
    "${TOPDIR}/CHANGES" "${TOPDIR}/docs/THANKS" "${TOPDIR}/docs/FAQ"    \
    "${TOPDIR}/docs/FEATURES" "${TOPDIR}/docs/SSLCERTS.md"              \
    "${TOPDIR}/docs/RESOURCES" "${TOPDIR}/docs/VERSIONS.md"             \
    "${TOPDIR}/docs/HISTORY.md"
do      MEMBER="`basename \"${TEXT}\" .OS400`"
        MEMBER="`basename \"${MEMBER}\" .md`"
        MEMBER="${LIBIFSNAME}/DOCS.FILE/`db2_name \"${MEMBER}\"`.MBR"

        [ -e "${TEXT}" ] || continue

        if action_needed "${MEMBER}" "${TEXT}"
        then    CMD="CPY OBJ('${TEXT}') TOOBJ('${MEMBER}') TOCCSID(${TGTCCSID})"
                CMD="${CMD} DTAFMT(*TEXT) REPLACE(*YES)"
                CLcommand "${CMD}"
        fi
done


#       Create the RPGXAMPLES source file if it does not exist.

if action_needed "${LIBIFSNAME}/RPGXAMPLES.FILE"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/RPGXAMPLES) RCDLEN(240)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('ILE/RPG examples')"
        CLcommand "${CMD}"
fi


#       Copy RPG examples if needed.

for EXAMPLE in "${SCRIPTDIR}/rpg-examples"/*
do      MEMBER="`basename \"${EXAMPLE}\"`"
        IFSMEMBER="${LIBIFSNAME}/RPGXAMPLES.FILE/`db2_name \"${MEMBER}\"`.MBR"

        [ -e "${EXAMPLE}" ] || continue

        if action_needed "${IFSMEMBER}" "${EXAMPLE}"
        then    CMD="CPY OBJ('${EXAMPLE}') TOOBJ('${IFSMEMBER}')"
                CMD="${CMD} TOCCSID(${TGTCCSID}) DTAFMT(*TEXT) REPLACE(*YES)"
                CLcommand "${CMD}"
                MBRTEXT=`sed -e '1!d;/^      \*/!d;s/^ *\* *//'         \
                             -e 's/ *$//;s/'"'"'/&&/g' < "${EXAMPLE}"`
                CMD="CHGPFM FILE(${TARGETLIB}/RPGXAMPLES) MBR(${MEMBER})"
                CMD="${CMD} SRCTYPE(RPGLE) TEXT('${MBRTEXT}')"
                CLcommand "${CMD}"
        fi
done


#       Build in each directory.

# for SUBDIR in include lib src tests
for SUBDIR in include lib src
do      "${SCRIPTDIR}/make-${SUBDIR}.sh"
done
