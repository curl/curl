
# Try to figure out  versioning scheme for dynamic libraries
# based on the system we're compiling for
function(determine_version_type _out_version_type_name)

        set(_ver_type "none")

        if(WIN32 OR CYGWIN)
                set(_ver_type "windows")
        else()
                # this part tries to mimic autotools as close as possible
                if(CMAKE_SYSTEM_NAME STREQUAL "AIX" OR
                   CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
                   CMAKE_SYSTEM_NAME STREQUAL "GNU/kFreeBSD" OR

                   # FreeBSD comes with the a.out and elf flavours
                   # but a.out was supported up to version 3.x and
                   # elf from 3.x. I cannot imagine someone runnig
                   # CMake on those ancient systems
                   CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR

                   CMAKE_SYSTEM_NAME STREQUAL "Haiku" OR
                   CMAKE_SYSTEM_NAME STREQUAL "SunOS")
                        set(_ver_type "linux")
                elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX" OR
                       CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
                       CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
                        set(_ver_type "sunos")
                elseif(CMAKE_SYSTEM_NAME STREQUAL "SCO_SV" OR
                       CMAKE_SYSTEM_NAME STREQUAL "UnixWare" OR
                       CMAKE_SYSTEM_NAME STREQUAL "UNIX_SV" OR
                       CMAKE_SYSTEM_NAME STREQUAL "XENIX" OR
                       QNXNTO)
                        set(_ver_type "sco/qnx")
                elseif(APPLE)
                        set(_ver_type "darwin")
                endif()
        endif()

        set(${_out_version_type_name} "${_ver_type}" PARENT_SCOPE)
endfunction()

# Take the libtool-specific version info in form CURRENT:REVISION:AGE
# and try to translate it to CMakes' VERSION / SOVERSION properties
function(parse_versioninfo _versioninfo_string _out_version_name _out_soversion_name)
        string(REPLACE ":" ";" _versioninfo_components ${_versioninfo_string})
        list(LENGTH _versioninfo_components _len)
        if(${_len} LESS 3)
                message(FATAL_ERROR "Version string '${_versioninfo_string}' is not a valid libtool value.")
        endif()

        list(GET _versioninfo_components 0 _current)
        list(GET _versioninfo_components 1 _revision)
        list(GET _versioninfo_components 2 _age)

        determine_version_type(_version_type)

        if(_version_type STREQUAL "linux")
                math(EXPR _major ${_current}-${_age})
                set(${_out_version_name} ${_major}.${_age}.${_revision} PARENT_SCOPE)
                set(${_out_soversion_name} ${_major} PARENT_SCOPE)
        elseif(_version_type STREQUAL "sco/qnx")
                set(${_out_version_name} ${_current} PARENT_SCOPE)
                set(${_out_soversion_name} ${_current} PARENT_SCOPE)
        elseif(_version_type STREQUAL "sunos")
                set(${_out_version_name} ${_current} PARENT_SCOPE)
                set(${_out_soversion_name} ${_current}.${_revision} PARENT_SCOPE)
        elseif(_version_type STREQUAL "darwin")
                math(EXPR _minor_current ${_current}+1)
                set(${_out_version_name} ${_minor_current}.${_revision} PARENT_SCOPE)
                set(${_out_soversion_name} ${_minor_current} PARENT_SCOPE)
        elseif(_version_type STREQUAL "windows")
                math(EXPR _major ${_current}-${_age})
                set(${_out_version_name} ${_major} PARENT_SCOPE)
        endif()
endfunction()

