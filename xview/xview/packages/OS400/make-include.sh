#!/bin/sh
#
#       Installation of the header files in the OS/400 library.
#

SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/include"


#       Produce the curlbuild.h header file if not yet in distribution (CVS).

if action_needed curl/curlbuild.h
then    if action_needed curl/curlbuild.h curl/curlbuild.h.dist
        then    cp -p curl/curlbuild.h.dist curl/curlbuild.h
        fi
fi


#       Create the OS/400 source program file for the header files.

SRCPF="${LIBIFSNAME}/H.FILE"

if action_needed "${SRCPF}"
then    CMD="CRTSRCPF FILE(${TARGETLIB}/H) RCDLEN(112)"
        CMD="${CMD} CCSID(${TGTCCSID}) TEXT('curl: Header files')"
        system "${CMD}"
fi


#       Create the IFS directory for the header files.

IFSINCLUDE="${IFSDIR}/include/curl"

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

for HFILE in curl/*.h ${SCRIPTDIR}/ccsidcurl.h
do      case "`basename \"${HFILE}\" .h`" in
        stdcheaders|typecheck-gcc)
                continue;;
        esac

        DEST="${SRCPF}/`db2_name \"${HFILE}\" nomangle`.MBR"

        if action_needed "${DEST}" "${HFILE}"
        then    copy_hfile "${DEST}" "${HFILE}"
                IFSDEST="${IFSINCLUDE}/`basename \"${HFILE}\"`"
                rm -f "${IFSDEST}"
                ln -s "${DEST}" "${IFSDEST}"
        fi
done


#       Copy the ILE/RPG header file, setting-up version number.

versioned_copy "${SCRIPTDIR}/curl.inc.in" "${SRCPF}/CURL.INC.MBR"
rm -f "${IFSINCLUDE}/curl.inc.rpgle"
ln -s "${SRCPF}/CURL.INC.MBR" "${IFSINCLUDE}/curl.inc.rpgle"


#       Duplicate file H as CURL to support more include path forms.

if action_needed "${LIBIFSNAME}/CURL.FILE"
then    :
else    system "DLTF FILE(${TARGETLIB}/CURL)"
fi

CMD="CRTDUPOBJ OBJ(H) FROMLIB(${TARGETLIB}) OBJTYPE(*FILE) TOLIB(*FROMLIB)"
CMD="${CMD} NEWOBJ(CURL) DATA(*YES)"
system "${CMD}"
