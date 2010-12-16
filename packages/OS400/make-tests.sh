#!/bin/sh
#
#       tests compilation script for the OS/400.
#


SCRIPTDIR=`dirname "${0}"`
. "${SCRIPTDIR}/initscript.sh"
cd "${TOPDIR}/tests"


#       tests directory not implemented yet.


#       Process the libtest subdirectory.

cd libtest

#       Get definitions from the Makefile.inc file.
#       The `sed' statement works as follows:
#       _ Join \nl-separated lines.
#       _ Retain only lines that begins with "identifier =".
#       _ Turn these lines into shell variable assignments.

eval "`sed -e ': begin'                                                 \
        -e '/\\\\$/{'                                                   \
        -e 'N'                                                          \
        -e 's/\\\\\\n/ /'                                               \
        -e 'b begin'                                                    \
        -e '}'                                                          \
        -e '/^[A-Za-z_][A-Za-z0-9_]*[ 	]*[=]/b keep'                   \
        -e 'd'                                                          \
        -e ': keep'                                                     \
        -e 's/[ 	]*=[ 	]*/=/'                                  \
        -e 's/=\\(.*[^ 	]\\)[ 	]*$/=\\"\\1\\"/'                        \
        -e 's/\\$(\\([^)]*\\))/${\\1}/g'                                \
        < Makefile.inc`"

#       Special case: redefine chkhostname compilation parameters.

chkhostname_SOURCES=chkhostname.c
chkhostname_LDADD=curl_gethostname.o

#       Compile all programs.
#       The list is found in variable "noinst_PROGRAMS"

INCLUDES="'${TOPDIR}/tests/libtest' '${TOPDIR}/lib'"

for PGM in ${noinst_PROGRAMS}
do      DB2PGM=`db2_name "${PGM}"`
        PGMIFSNAME="${LIBIFSNAME}/${DB2PGM}.PGM"

        #       Extract preprocessor symbol definitions from compilation
        #               options for the program.

        PGMCFLAGS="`eval echo \"\\${${PGM}_CFLAGS}\"`"
        PGMDEFINES=

        for FLAG in ${PGMCFLAGS}
        do      case "${FLAG}" in
                -D?*)   DEFINE="`echo \"${FLAG}\" | sed 's/^..//'`"
                        PGMDEFINES="${PGMDEFINES} '${DEFINE}'"
                        ;;
                esac
        done

        #        Compile all C sources for the program into modules.

        PGMSOURCES="`eval echo \"\\${${PGM}_SOURCES}\"`"
        LINK=
        MODULES=

        for SOURCE in ${PGMSOURCES}
        do      case "${SOURCE}" in
                *.c)    #       Special processing for libxxx.c files: their
                        #               module name is determined by the target
                        #               PROGRAM name.

                        case "${SOURCE}" in
                        lib*.c) MODULE="${DB2PGM}"
                                ;;
                        *)      MODULE=`db2_name "${SOURCE}"`
                                ;;
                        esac

                        make_module "${MODULE}" "${SOURCE}" "${PGMDEFINES}"
                        if action_needed "${PGMIFSNAME}" "${MODIFSNAME}"
                        then    LINK=yes
                        fi
                        ;;
                esac
        done

        #       Link program if needed.

        if [ "${LINK}" ]
        then    PGMLDADD="`eval echo \"\\${${PGM}_LDADD}\"`"
                for LDARG in ${PGMLDADD}
                do      case "${LDARG}" in
                        -*)     ;;              # Ignore non-module.
                        *)      MODULES="${MODULES} "`db2_name "${LDARG}"`
                                ;;
                        esac
                done
                MODULES="`echo \"${MODULES}\" |
                    sed \"s/[^ ][^ ]*/${TARGETLIB}\/&/g\"`"
                CMD="CRTPGM PGM(${TARGETLIB}/${DB2PGM})"
                CMD="${CMD} ENTMOD(QADRT/QADRTMAIN2)"
                CMD="${CMD} MODULE(${MODULES})"
                CMD="${CMD} BNDSRVPGM(${TARGETLIB}/${SRVPGM} QADRTTS)"
                CMD="${CMD} TGTRLS(${TGTRLS})"
                system "${CMD}"
        fi
done
