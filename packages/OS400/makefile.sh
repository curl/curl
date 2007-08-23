#!/bin/sh
#
#       curl compilation script for the OS/400.
#
# $Id$
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


#       Build in each directory.

for SUBDIR in include lib src tests
do      "${SCRIPTDIR}/make-${SUBDIR}.sh"
done
