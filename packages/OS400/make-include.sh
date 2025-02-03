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
#
#       Installation of the header files in the OS/400 library.
#

SCRIPTDIR=$(dirname "${0}")
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/include" || exit 1


#       Create the OS/400 source program file for the header files.

SRCPF="${LIBIFSNAME}/H.FILE"

if action_needed "${SRCPF}"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/H) RCDLEN(112)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('fetch: Header files')"
        CLcommand "${CMD}"
fi


#       Create the IFS directory for the header files.

IFSINCLUDE="${IFSDIR}/include/fetch"

if action_needed "${IFSINCLUDE}"
then    mkdir -p "${IFSINCLUDE}"
fi


#       Enumeration values are used as va_arg tagfields, so they MUST be
#               integers.

copy_hfile()

{
        destfile="${1}"
        srcfile="${2}"
        shift
        shift
        sed -e '1i\
#pragma enum(int)\
' "${@}" -e '$a\
#pragma enum(pop)\
' < "${srcfile}" > "${destfile}"
}

#       Copy the header files.

for HFILE in fetch/*.h ${SCRIPTDIR}/ccsidfetch.h
do      case "$(basename "${HFILE}" .h)" in
        stdcheaders|typecheck-gcc)
                continue;;
        esac

        DEST="${SRCPF}/$(db2_name "${HFILE}" nomangle).MBR"

        if action_needed "${DEST}" "${HFILE}"
        then    copy_hfile "${DEST}" "${HFILE}"
                IFSDEST="${IFSINCLUDE}/$(basename "${HFILE}")"
                rm -f "${IFSDEST}"
                ln -s "${DEST}" "${IFSDEST}"
        fi
done


#       Copy the ILE/RPG header file, setting-up version number.

versioned_copy "${SCRIPTDIR}/fetch.inc.in" "${SRCPF}/FETCH.INC.MBR"
rm -f "${IFSINCLUDE}/fetch.inc.rpgle"
ln -s "${SRCPF}/FETCH.INC.MBR" "${IFSINCLUDE}/fetch.inc.rpgle"


#       Duplicate file H as FETCH to support more include path forms.

if action_needed "${LIBIFSNAME}/FETCH.FILE"
then    :
else    CLcommand "DLTF FILE(${TARGETLIB}/FETCH)"
fi

CMD="CRTDUPOBJ OBJ(H) FROMLIB(${TARGETLIB}) OBJTYPE(*FILE) TOLIB(*FROMLIB)"
CMD="${CMD} NEWOBJ(FETCH) DATA(*YES)"
CLcommand "${CMD}"
