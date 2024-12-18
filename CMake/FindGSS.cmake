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
# Find the GSS Kerberos library
#
# Input variables:
#
# - `GSS_ROOT_DIR`:      Set this variable to the root installation of GSS. (also supported as environment)
#
# Result variables:
#
# - `GSS_FOUND`:         System has the Heimdal library.
# - `GSS_FLAVOUR`:       "GNU", "MIT" or "Heimdal" if anything found.
# - `GSS_INCLUDE_DIRS`:  The GSS include directories.
# - `GSS_LIBRARIES`:     The GSS library names.
# - `GSS_LIBRARY_DIRS`:  The GSS library directories.
# - `GSS_PC_REQUIRES`:   The GSS pkg-config packages.
# - `GSS_CFLAGS`:        Required compiler flags.
# - `GSS_VERSION`:       This is set to version advertised by pkg-config or read from manifest.
#                        In case the library is found but no version info available it is set to "unknown"

set(_gnu_modname "gss")
set(_mit_modname "mit-krb5-gssapi")
set(_heimdal_modname "heimdal-gssapi")

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

set(_gss_root_hints
  "${GSS_ROOT_DIR}"
  "$ENV{GSS_ROOT_DIR}"
)

# Try to find library using system pkg-config if user did not specify root dir
if(NOT GSS_ROOT_DIR AND NOT "$ENV{GSS_ROOT_DIR}")
  if(CURL_USE_PKGCONFIG)
    find_package(PkgConfig QUIET)
    pkg_search_module(_GSS ${_gnu_modname} ${_mit_modname} ${_heimdal_modname})
    list(APPEND _gss_root_hints "${_GSS_PREFIX}")
  endif()
  if(WIN32)
    list(APPEND _gss_root_hints "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
  endif()
endif()

if(NOT _GSS_FOUND)  # Not found by pkg-config. Let us take more traditional approach.
  find_file(_gss_configure_script
    NAMES
      "krb5-config"
    HINTS
      ${_gss_root_hints}
    PATH_SUFFIXES
      "bin"
    NO_CMAKE_PATH
    NO_CMAKE_ENVIRONMENT_PATH
  )

  # If not found in user-supplied directories, maybe system knows better
  find_file(_gss_configure_script
    NAMES
      "krb5-config"
    PATH_SUFFIXES
      "bin"
  )

  if(_gss_configure_script)
    execute_process(
      COMMAND ${_gss_configure_script} "--cflags" "gssapi"
      OUTPUT_VARIABLE _GSS_CFLAGS
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "FindGSS krb5-config --cflags: ${_GSS_CFLAGS}")
    if(NOT _gss_configure_failed)  # 0 means success
      # Should also work in an odd case when multiple directories are given
      string(STRIP "${_GSS_CFLAGS}" _GSS_CFLAGS)
      string(REGEX REPLACE " +-I" ";" _GSS_CFLAGS "${_GSS_CFLAGS}")
      string(REGEX REPLACE " +-([^I][^ \\t;]*)" ";-\\1" _GSS_CFLAGS "${_GSS_CFLAGS}")

      foreach(_flag IN LISTS _GSS_CFLAGS)
        if(_flag MATCHES "^-I")
          string(REGEX REPLACE "^-I" "" _val "${_flag}")
          list(APPEND _GSS_INCLUDE_DIRS "${_val}")
        else()
          list(APPEND _GSS_CFLAGS "${_flag}")
        endif()
      endforeach()
    endif()

    execute_process(
      COMMAND ${_gss_configure_script} "--libs" "gssapi"
      OUTPUT_VARIABLE _gss_lib_flags
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "FindGSS krb5-config --libs: ${_gss_lib_flags}")

    if(NOT _gss_configure_failed)  # 0 means success
      # This script gives us libraries and link directories. Blah. We have to deal with it.
      string(STRIP "${_gss_lib_flags}" _gss_lib_flags)
      string(REGEX REPLACE " +-(L|l)" ";-\\1" _gss_lib_flags "${_gss_lib_flags}")
      string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _gss_lib_flags "${_gss_lib_flags}")

      foreach(_flag IN LISTS _gss_lib_flags)
        if(_flag MATCHES "^-l")
          string(REGEX REPLACE "^-l" "" _val "${_flag}")
          list(APPEND _GSS_LIBRARIES "${_val}")
        elseif(_flag MATCHES "^-L")
          string(REGEX REPLACE "^-L" "" _val "${_flag}")
          list(APPEND _GSS_LIBRARY_DIRS "${_val}")
        endif()
      endforeach()
    endif()

    execute_process(
      COMMAND ${_gss_configure_script} "--version"
      OUTPUT_VARIABLE _GSS_VERSION
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Older versions may not have the "--version" parameter. In this case we just do not care.
    if(_gss_configure_failed)
      set(_GSS_VERSION 0)
    endif()

    execute_process(
      COMMAND ${_gss_configure_script} "--vendor"
      OUTPUT_VARIABLE _gss_vendor
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Older versions may not have the "--vendor" parameter. In this case we just do not care.
    if(_gss_configure_failed)
      set(GSS_FLAVOUR "Heimdal")  # most probably, should not really matter
    else()
      if(_gss_vendor MATCHES "H|heimdal")
        set(GSS_FLAVOUR "Heimdal")
      else()
        set(GSS_FLAVOUR "MIT")
      endif()
    endif()

  else()  # Either there is no config script or we are on a platform that does not provide one (Windows?)

    find_path(_GSS_INCLUDE_DIRS NAMES "gssapi/gssapi.h"
      HINTS
        ${_gss_root_hints}
      PATH_SUFFIXES
        "include"
        "inc"
    )

    if(_GSS_INCLUDE_DIRS)  # jay, we have found something
      cmake_push_check_state()
      list(APPEND CMAKE_REQUIRED_INCLUDES "${_GSS_INCLUDE_DIRS}")
      check_include_files("gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" _gss_have_mit_headers)

      if(_gss_have_mit_headers)
        set(GSS_FLAVOUR "MIT")
      else()
        # Prevent compiling the header - just check if we can include it
        list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D__ROKEN_H__")
        check_include_file("roken.h" _gss_have_roken_h)

        check_include_file("heimdal/roken.h" _gss_have_heimdal_roken_h)
        if(_gss_have_roken_h OR _gss_have_heimdal_roken_h)
          set(GSS_FLAVOUR "Heimdal")
        endif()
      endif()
      cmake_pop_check_state()
    else()
      # I am not convinced if this is the right way but this is what autotools do at the moment
      find_path(_GSS_INCLUDE_DIRS NAMES "gssapi.h"
        HINTS
          ${_gss_root_hints}
        PATH_SUFFIXES
          "include"
          "inc"
      )

      if(_GSS_INCLUDE_DIRS)
        set(GSS_FLAVOUR "Heimdal")
      else()
        find_path(_GSS_INCLUDE_DIRS NAMES "gss.h"
          HINTS
            ${_gss_root_hints}
          PATH_SUFFIXES
            "include"
        )

        if(_GSS_INCLUDE_DIRS)
          set(GSS_FLAVOUR "GNU")
          set(GSS_PC_REQUIRES "gss")
        endif()
      endif()
    endif()

    # If we have headers, check if we can link libraries
    if(GSS_FLAVOUR)
      set(_gss_libdir_suffixes "")
      set(_gss_libdir_hints ${_gss_root_hints})
      get_filename_component(_gss_calculated_potential_root "${_GSS_INCLUDE_DIRS}" DIRECTORY)
      list(APPEND _gss_libdir_hints ${_gss_calculated_potential_root})

      if(WIN32)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
          list(APPEND _gss_libdir_suffixes "lib/AMD64")
          if(GSS_FLAVOUR STREQUAL "GNU")
            set(_gss_libname "gss")
          elseif(GSS_FLAVOUR STREQUAL "MIT")
            set(_gss_libname "gssapi64")
          else()
            set(_gss_libname "libgssapi")
          endif()
        else()
          list(APPEND _gss_libdir_suffixes "lib/i386")
          if(GSS_FLAVOUR STREQUAL "GNU")
            set(_gss_libname "gss")
          elseif(GSS_FLAVOUR STREQUAL "MIT")
            set(_gss_libname "gssapi32")
          else()
            set(_gss_libname "libgssapi")
          endif()
        endif()
      else()
        list(APPEND _gss_libdir_suffixes "lib;lib64")  # those suffixes are not checked for HINTS
        if(GSS_FLAVOUR STREQUAL "GNU")
          set(_gss_libname "gss")
        elseif(GSS_FLAVOUR STREQUAL "MIT")
          set(_gss_libname "gssapi_krb5")
        else()
          set(_gss_libname "gssapi")
        endif()
      endif()

      find_library(_GSS_LIBRARIES NAMES ${_gss_libname}
        HINTS
          ${_gss_libdir_hints}
        PATH_SUFFIXES
          ${_gss_libdir_suffixes}
      )
    endif()
  endif()
else()
  # _GSS_MODULE_NAME set since CMake 3.16
  if(_GSS_MODULE_NAME STREQUAL _gnu_modname OR _GSS_${_gnu_modname}_VERSION)
    set(GSS_FLAVOUR "GNU")
    set(GSS_PC_REQUIRES "gss")
    if(NOT _GSS_VERSION)  # for old CMake versions?
      set(_GSS_VERSION ${_GSS_${_gnu_modname}_VERSION})
    endif()
  elseif(_GSS_MODULE_NAME STREQUAL _mit_modname OR _GSS_${_mit_modname}_VERSION)
    set(GSS_FLAVOUR "MIT")
    set(GSS_PC_REQUIRES "mit-krb5-gssapi")
    if(NOT _GSS_VERSION)  # for old CMake versions?
      set(_GSS_VERSION ${_GSS_${_mit_modname}_VERSION})
    endif()
  else()
    set(GSS_FLAVOUR "Heimdal")
    set(GSS_PC_REQUIRES "heimdal-gssapi")
    if(NOT _GSS_VERSION)  # for old CMake versions?
      set(_GSS_VERSION ${_GSS_${_heimdal_modname}_VERSION})
    endif()
  endif()
  message(STATUS "Found GSS/${GSS_FLAVOUR} (via pkg-config): ${_GSS_INCLUDE_DIRS} (found version \"${_GSS_VERSION}\")")
endif()

string(REPLACE ";" " " _GSS_CFLAGS "${_GSS_CFLAGS}")

set(GSS_INCLUDE_DIRS ${_GSS_INCLUDE_DIRS})
set(GSS_LIBRARIES ${_GSS_LIBRARIES})
set(GSS_LIBRARY_DIRS ${_GSS_LIBRARY_DIRS})
set(GSS_CFLAGS ${_GSS_CFLAGS})
set(GSS_VERSION ${_GSS_VERSION})

if(GSS_FLAVOUR)
  if(NOT GSS_VERSION AND GSS_FLAVOUR STREQUAL "Heimdal")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_heimdal_manifest_file "Heimdal.Application.amd64.manifest")
    else()
      set(_heimdal_manifest_file "Heimdal.Application.x86.manifest")
    endif()

    if(EXISTS "${GSS_INCLUDE_DIRS}/${_heimdal_manifest_file}")
      file(STRINGS "${GSS_INCLUDE_DIRS}/${_heimdal_manifest_file}" _heimdal_version_str
        REGEX "^.*version=\"[0-9]\\.[^\"]+\".*$")

      string(REGEX MATCH "[0-9]\\.[^\"]+" GSS_VERSION "${_heimdal_version_str}")
    endif()

    if(NOT GSS_VERSION)
      set(GSS_VERSION "Heimdal Unknown")
    endif()
  elseif(NOT GSS_VERSION AND GSS_FLAVOUR STREQUAL "MIT")
    get_filename_component(_mit_version "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos\\SDK\\CurrentVersion;VersionString]" NAME
      CACHE)
    if(WIN32 AND _mit_version)
      set(GSS_VERSION "${_mit_version}")
    else()
      set(GSS_VERSION "MIT Unknown")
    endif()
  elseif(NOT GSS_VERSION AND GSS_FLAVOUR STREQUAL "GNU")
    if(GSS_INCLUDE_DIRS AND EXISTS "${GSS_INCLUDE_DIRS}/gss.h")
      set(_version_regex "#[\t ]*define[\t ]+GSS_VERSION[\t ]+\"([^\"]*)\"")
      file(STRINGS "${GSS_INCLUDE_DIRS}/gss.h" _version_str REGEX "${_version_regex}")
      string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
      set(GSS_VERSION "${_version_str}")
      unset(_version_regex)
      unset(_version_str)
    endif()
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSS
  REQUIRED_VARS
    GSS_FLAVOUR
    GSS_LIBRARIES
  VERSION_VAR
    GSS_VERSION
  FAIL_MESSAGE
    "Could NOT find GSS, try to set the path to GSS root folder in the system variable GSS_ROOT_DIR"
)

mark_as_advanced(
  _GSS_CFLAGS
  _GSS_FOUND
  _GSS_INCLUDE_DIRS
  _GSS_LIBRARIES
  _GSS_LIBRARY_DIRS
  _GSS_MODULE_NAME
  _GSS_PREFIX
  _GSS_VERSION
)
