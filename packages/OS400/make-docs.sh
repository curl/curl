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
#       Documentation build script for the OS/400.
#


SCRIPTDIR=$(dirname "${0}")
. "${SCRIPTDIR}/initscript.sh"

[ -n "${PASEPERL}" ] || exit 0  # Perl needed for doc build.
cd "${TOPDIR}/docs" || exit 1
[ -d "${IFSDIR}/docs" ] || mkdir "${IFSDIR}/docs"


#       Command line options.

(
        cd cmdline-opts || exit 1
        MANPAGE=curl.1
        TEXTPAGE=curl.txt
        get_make_vars Makefile.inc
        rm -f "${IFSDIR}/docs/${MANPAGE}" "${IFSDIR}/docs/${TEXTPAGE}"

        #       Prepare online manual.
        # shellcheck disable=SC2086
        ${PASEPERL} "${TOPDIR}/scripts/managen" -c 75                   \
                listhelp ${DPAGES} > "${TOPDIR}/src/tool_listhelp.c"

        #       Generate text manual and copy it to DB2.
        # shellcheck disable=SC2086
        ${PASEPERL} "${TOPDIR}/scripts/managen" -I "${TOPDIR}/include"  \
               -c 75 ascii ${DPAGES} > "${IFSDIR}/docs/${TEXTPAGE}"
        MEMBER="${LIBIFSNAME}/DOCS.FILE/MANUAL.MBR"
        CMD="CPY OBJ('${IFSDIR}/docs/${TEXTPAGE}') TOOBJ('${MEMBER}')"
        CMD="${CMD} TOCCSID(${TGTCCSID}) DTAFMT(*TEXT) REPLACE(*YES)"
        CLcommand "${CMD}"

#       Man page is useless as OS/400 has no man command.
#       # shellcheck disable=SC2086
#       ${PASEPERL} "${TOPDIR}/scripts/managen" -I "${TOPDIR}/include"  \
#               mainpage ${DPAGES} > "${IFSDIR}/docs/${MANPAGE}"
)
