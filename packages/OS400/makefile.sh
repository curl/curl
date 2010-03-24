#!/bin/sh
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
        system "${CMD}"
fi


#       Create the DOCS source file if it does not exist.

if action_needed "${LIBIFSNAME}/DOCS.FILE"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/DOCS) RCDLEN(112)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('Documentation texts')"
        system "${CMD}"
fi


#       Copy some documentation files if needed.

for TEXT in "${TOPDIR}/COPYING" "${SCRIPTDIR}/README.OS400"             \
    "${TOPDIR}/CHANGES" "${TOPDIR}/docs/THANKS" "${TOPDIR}/docs/FAQ"    \
    "${TOPDIR}/docs/FEATURES" "${TOPDIR}/docs/SSLCERTS"                 \
    "${TOPDIR}/docs/RESOURCES" "${TOPDIR}/docs/VERSIONS"                \
    "${TOPDIR}/docs/HISTORY"
do      MEMBER="`basename \"${TEXT}\" .OS400`"
        MEMBER="${LIBIFSNAME}/DOCS.FILE/`db2_name \"${MEMBER}\"`.MBR"

        if action_needed "${MEMBER}" "${TEXT}"
        then    CMD="CPY OBJ('${TEXT}') TOOBJ('${MEMBER}') TOCCSID(${TGTCCSID})"
                CMD="${CMD} DTAFMT(*TEXT) REPLACE(*YES)"
                system "${CMD}"
        fi
done


#       Build in each directory.

for SUBDIR in include lib src tests
do      "${SCRIPTDIR}/make-${SUBDIR}.sh"
done
