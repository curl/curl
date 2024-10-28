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

CLcommand()
{
        /usr/bin/system "${@}" || exit 1
}

setenv()

{
        #       Define and export.

        eval "${1}=${2}"
        export "${1?}"
}


case "${SCRIPTDIR}" in
/*)     ;;
*)      SCRIPTDIR="$(pwd)/${SCRIPTDIR}"
esac

while true
do      case "${SCRIPTDIR}" in
        */.)    SCRIPTDIR="${SCRIPTDIR%/.}";;
        *)      break;;
        esac
done

#  The script directory is supposed to be in $TOPDIR/packages/os400.

TOPDIR=$(dirname "${SCRIPTDIR}")
TOPDIR=$(dirname "${TOPDIR}")
export SCRIPTDIR TOPDIR

#  Extract the SONAME from the library makefile.

SONAME="$(sed -e '/^VERSIONCHANGE=/!d;s/^.*=\([0-9]*\).*/\1/'           \
                                        < "${TOPDIR}/lib/Makefile.soname")"
export SONAME

#       Get OS/400 configuration parameters.

. "${SCRIPTDIR}/config400.default"
if [ -f "${SCRIPTDIR}/config400.override" ]
then    . "${SCRIPTDIR}/config400.override"
fi

#       Check if perl available.
{ [ -n "${PASEPERL}" ] && [ -x "${PASEPERL}" ]; } || PASEPERL=

#       Need to get the version definitions.

LIBCURL_VERSION=$(grep '^#define  *LIBCURL_VERSION '                    \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/.*"\(.*\)".*/\1/')
LIBCURL_VERSION_MAJOR=$(grep '^#define  *LIBCURL_VERSION_MAJOR '        \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/^#define  *LIBCURL_VERSION_MAJOR  *\([^ ]*\).*/\1/')
LIBCURL_VERSION_MINOR=$(grep '^#define  *LIBCURL_VERSION_MINOR '        \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/^#define  *LIBCURL_VERSION_MINOR  *\([^ ]*\).*/\1/')
LIBCURL_VERSION_PATCH=$(grep '^#define  *LIBCURL_VERSION_PATCH '        \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/^#define  *LIBCURL_VERSION_PATCH  *\([^ ]*\).*/\1/')
LIBCURL_VERSION_NUM=$(grep '^#define  *LIBCURL_VERSION_NUM '            \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/^#define  *LIBCURL_VERSION_NUM  *0x\([^ ]*\).*/\1/')
LIBCURL_TIMESTAMP=$(grep '^#define  *LIBCURL_TIMESTAMP '                \
                        "${TOPDIR}/include/curl/curlver.h"              |
                sed 's/.*"\(.*\)".*/\1/')
export LIBCURL_VERSION
export LIBCURL_VERSION_MAJOR LIBCURL_VERSION_MINOR LIBCURL_VERSION_PATCH
export LIBCURL_VERSION_NUM LIBCURL_TIMESTAMP

################################################################################
#
#                       OS/400 specific definitions.
#
################################################################################

LIBIFSNAME="/QSYS.LIB/${TARGETLIB}.LIB"


################################################################################
#
#                               Procedures.
#
################################################################################

#       action_needed dest [src]
#
#       dest is an object to build
#       if specified, src is an object on which dest depends.
#
#       exit 0 (succeeds) if some action has to be taken, else 1.

action_needed()

{
        [ ! -e "${1}" ] && return 0
        [ -n "${2}" ] || return 1
        # shellcheck disable=SC3013
        [ "${1}" -ot "${2}" ] && return 0
        return 1
}


#       canonicalize_path path
#
#       Return canonicalized path as:
#       - Absolute
#       - No . or .. component.

canonicalize_path()

{
        if expr "${1}" : '^/' > /dev/null
        then    P="${1}"
        else    P="$(pwd)/${1}"
        fi

        R=
        IFSSAVE="${IFS}"
        IFS="/"

        for C in ${P}
        do      IFS="${IFSSAVE}"
                case "${C}" in
                .)      ;;
                ..)     R="$(expr "${R}" : '^\(.*/\)..*')"
                        ;;
                ?*)     R="${R}${C}/"
                        ;;
                *)      ;;
                esac
        done

        IFS="${IFSSAVE}"
        echo "/$(expr "${R}" : '^\(.*\)/')"
}


#       make_module module_name source_name [additional_definitions]
#
#       Compile source name into ASCII module if needed.
#       As side effect, append the module name to variable MODULES.
#       Set LINK to "YES" if the module has been compiled.

make_module()

{
        MODULES="${MODULES} ${1}"
        MODIFSNAME="${LIBIFSNAME}/${1}.MODULE"
        action_needed "${MODIFSNAME}" "${2}" || return 0;
        SRCDIR="$(dirname "$(canonicalize_path "${2}")")"

        #       #pragma convert has to be in the source file itself, i.e.
        #               putting it in an include file makes it only active
        #               for that include file.
        #       Thus we build a temporary file with the pragma prepended to
        #               the source file and we compile that temporary file.

        {
                echo "#line 1 \"${2}\""
                echo "#pragma convert(819)"
                echo "#line 1"
                cat "${2}"
        } > "${1}"__819.c
        CMD="CRTCMOD MODULE(${TARGETLIB}/${1}) SRCSTMF('${1}__819.c')"
        CMD="${CMD} SYSIFCOPT(*IFS64IO *ASYNCSIGNAL)"
#       CMD="${CMD} OPTION(*INCDIRFIRST *SHOWINC *SHOWSYS)"
        CMD="${CMD} OPTION(*INCDIRFIRST)"
        CMD="${CMD} LOCALETYPE(*LOCALE) FLAG(10)"
        CMD="${CMD} INCDIR('${QADRTDIR}/include'"
        CMD="${CMD} '${TOPDIR}/include/curl' '${TOPDIR}/include' '${SRCDIR}'"
        CMD="${CMD} '${TOPDIR}/packages/OS400'"

        if [ "${WITH_ZLIB}" != "0" ]
        then    CMD="${CMD} '${ZLIB_INCLUDE}'"
        fi

        if [ "${WITH_LIBSSH2}" != "0" ]
        then    CMD="${CMD} '${LIBSSH2_INCLUDE}'"
        fi

        CMD="${CMD} ${INCLUDES})"
        CMD="${CMD} TGTCCSID(${TGTCCSID}) TGTRLS(${TGTRLS})"
        CMD="${CMD} OUTPUT(${OUTPUT})"
        CMD="${CMD} OPTIMIZE(${OPTIMIZE})"
        CMD="${CMD} DBGVIEW(${DEBUG})"

        DEFINES="${3} 'qadrt_use_inline'"

        if [ "${WITH_ZLIB}" != "0" ]
        then    DEFINES="${DEFINES} HAVE_LIBZ"
        fi

        if [ "${WITH_LIBSSH2}" != "0" ]
        then    DEFINES="${DEFINES} USE_LIBSSH2"
        fi

        if [ -n "${DEFINES}" ]
        then    CMD="${CMD} DEFINE(${DEFINES})"
        fi

        CLcommand "${CMD}"
        if [ "${DEBUG}" = "*NONE" ]
        then    rm -f "${1}"__819.c
        fi
        # shellcheck disable=SC2034
        LINK=YES
}


#       Determine DB2 object name from IFS name.

db2_name()

{
        if [ "${2}" = 'nomangle' ]
        then    basename "${1}"                                         |
                tr 'a-z-' 'A-Z_'                                        |
                sed -e 's/\..*//'                                       \
                    -e 's/^\(.\).*\(.........\)$/\1\2/'
        else    basename "${1}"                                         |
                tr 'a-z-' 'A-Z_'                                        |
                sed -e 's/\..*//'                                       \
                    -e 's/^CURL_*/C/'                                   \
                    -e 's/^TOOL_*/T/'                                   \
                    -e 's/^\(.\).*\(.........\)$/\1\2/'
        fi
}


#       Copy IFS file replacing version info.

versioned_copy()

{
        sed -e "s/@LIBCURL_VERSION@/${LIBCURL_VERSION}/g"               \
            -e "s/@LIBCURL_VERSION_MAJOR@/${LIBCURL_VERSION_MAJOR}/g"   \
            -e "s/@LIBCURL_VERSION_MINOR@/${LIBCURL_VERSION_MINOR}/g"   \
            -e "s/@LIBCURL_VERSION_PATCH@/${LIBCURL_VERSION_PATCH}/g"   \
            -e "s/@LIBCURL_VERSION_NUM@/${LIBCURL_VERSION_NUM}/g"       \
            -e "s/@LIBCURL_TIMESTAMP@/${LIBCURL_TIMESTAMP}/g"           \
                < "${1}" > "${2}"
}


#       Get definitions from a make file.
#       The `sed' statement works as follows:
#       - Join \nl-separated lines.
#       - Retain only lines that begins with "identifier =".
#       - Replace @...@ substitutions by shell variable references.
#       - Turn these lines into shell variable assignments.

get_make_vars()

{
        eval "$(sed -e ': begin'                                        \
                -e '/\\$/{'                                             \
                -e 'N'                                                  \
                -e 's/\\\n/ /'                                          \
                -e 'b begin'                                            \
                -e '}'                                                  \
                -e 's/[[:space:]][[:space:]]*/ /g'                      \
                -e '/^[A-Za-z_][A-Za-z0-9_]* *=/!d'                     \
                -e 's/@\([A-Za-z0-9_]*\)@/${\1}/g'                      \
                -e 's/ *= */=/'                                         \
                -e 's/=\(.*[^ ]\) *$/="\1"/'                            \
                -e 's/\$(\([^)]*\))/${\1}/g'                            \
                < "${1}")"
}
