#!/bin/sh
#
#       Installation of the include files in the OS/400 library.
#
# $Id$

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/include"


#       Create the OS/400 source program file for the include files.

SRCPF="${LIBIFSNAME}/H.FILE"

if action_needed "${SRCPF}"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/H) RCDLEN(112)"
        CMD="${CMD} TEXT('curl: Header files')"
        system "${CMD}"
fi


#       Enumeration values are used as va_arg tagfields, so they MUST be
#               integers.

copy_hfile()

{
        sed -e '1i\
#pragma enum(int)\
' -e '$a\
#pragma enum(pop)\
' < "${2}" > "${1}"
}

#       Copy the header files.

for HFILE in curl/*.h ${SCRIPTDIR}/ccsidcurl.h
do      DEST="${SRCPF}/`db2_name \"${HFILE}\"`.MBR"
        if action_needed "${DEST}" "${HFILE}"
        then    copy_hfile "${DEST}" "${HFILE}"
        fi
done


#       Copy the ILE/RPG include file, setting-up version number.

        versioned_copy "${SCRIPTDIR}/curl.inc.in" "${SRCPF}/CURL.INC.MBR"
