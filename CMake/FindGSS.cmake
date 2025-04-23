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
# - `GSS_ROOT_DIR`:       Absolute path to the root installation of GSS. (also supported as environment)
#
# Defines:
#
# - `GSS_FOUND`:          System has a GSS library.
# - `GSS_VERSION`:        This is set to version advertised by pkg-config or read from manifest.
#                         In case the library is found but no version info available it is set to "unknown"
# - `CURL::gss`:          GSS library target.
#   - CURL_GSS_FLAVOUR`:  Custom property. "GNU" or "MIT" if detected.

set(_gnu_modname "gss")
set(_mit_modname "mit-krb5-gssapi")

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

set(_gss_root_hints "${GSS_ROOT_DIR}" "$ENV{GSS_ROOT_DIR}")

set(_gss_CFLAGS "")
set(_gss_LIBRARY_DIRS "")

# Try to find library using system pkg-config if user did not specify root dir
if(NOT GSS_ROOT_DIR AND NOT "$ENV{GSS_ROOT_DIR}")
  if(CURL_USE_PKGCONFIG)
    find_package(PkgConfig QUIET)
    pkg_search_module(_gss ${_gnu_modname} ${_mit_modname})
    list(APPEND _gss_root_hints "${_gss_PREFIX}")
    set(_gss_version "${_gss_VERSION}")
  endif()
  if(WIN32)
    list(APPEND _gss_root_hints "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
  endif()
endif()

if(NOT _gss_FOUND)  # Not found by pkg-config. Let us take more traditional approach.
  find_file(_gss_configure_script NAMES "krb5-config" PATH_SUFFIXES "bin" HINTS ${_gss_root_hints}
    NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH)
  # If not found in user-supplied directories, maybe system knows better
  find_file(_gss_configure_script NAMES "krb5-config" PATH_SUFFIXES "bin")

  if(_gss_configure_script)

    set(_gss_INCLUDE_DIRS "")
    set(_gss_LIBRARIES "")

    execute_process(COMMAND ${_gss_configure_script} "--cflags" "gssapi"
      OUTPUT_VARIABLE _gss_cflags_raw
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "FindGSS krb5-config --cflags: ${_gss_cflags_raw}")

    if(NOT _gss_configure_failed)  # 0 means success
      # Should also work in an odd case when multiple directories are given.
      string(STRIP "${_gss_cflags_raw}" _gss_cflags_raw)
      string(REGEX REPLACE " +-(I)" ";-\\1" _gss_cflags_raw "${_gss_cflags_raw}")
      string(REGEX REPLACE " +-([^I][^ \\t;]*)" ";-\\1" _gss_cflags_raw "${_gss_cflags_raw}")

      foreach(_flag IN LISTS _gss_cflags_raw)
        if(_flag MATCHES "^-I")
          string(REGEX REPLACE "^-I" "" _flag "${_flag}")
          list(APPEND _gss_INCLUDE_DIRS "${_flag}")
        else()
          list(APPEND _gss_CFLAGS "${_flag}")
        endif()
      endforeach()
    endif()

    execute_process(COMMAND ${_gss_configure_script} "--libs" "gssapi"
      OUTPUT_VARIABLE _gss_lib_flags
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "FindGSS krb5-config --libs: ${_gss_lib_flags}")

    if(NOT _gss_configure_failed)  # 0 means success
      # This script gives us libraries and link directories.
      string(STRIP "${_gss_lib_flags}" _gss_lib_flags)
      string(REGEX REPLACE " +-(L|l)" ";-\\1" _gss_lib_flags "${_gss_lib_flags}")
      string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _gss_lib_flags "${_gss_lib_flags}")

      foreach(_flag IN LISTS _gss_lib_flags)
        if(_flag MATCHES "^-l")
          string(REGEX REPLACE "^-l" "" _flag "${_flag}")
          list(APPEND _gss_LIBRARIES "${_flag}")
        elseif(_flag MATCHES "^-L")
          string(REGEX REPLACE "^-L" "" _flag "${_flag}")
          list(APPEND _gss_LIBRARY_DIRS "${_flag}")
        endif()
      endforeach()
    endif()

    execute_process(COMMAND ${_gss_configure_script} "--version"
      OUTPUT_VARIABLE _gss_version
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Older versions may not have the "--version" parameter. In this case we just do not care.
    if(_gss_configure_failed)
      set(_gss_version 0)
    else()
      # Strip prefix string to leave the version number only
      string(REPLACE "Kerberos 5 release " "" _gss_version "${_gss_version}")
    endif()

    execute_process(COMMAND ${_gss_configure_script} "--vendor"
      OUTPUT_VARIABLE _gss_vendor
      RESULT_VARIABLE _gss_configure_failed
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Older versions may not have the "--vendor" parameter. In this case we just do not care.
    if(NOT _gss_configure_failed AND NOT _gss_vendor MATCHES "Heimdal|heimdal")
      set(_gss_flavour "MIT")  # assume a default, should not really matter
    endif()

  else()  # Either there is no config script or we are on a platform that does not provide one (Windows?)

    find_path(_gss_INCLUDE_DIRS NAMES "gssapi/gssapi.h" HINTS ${_gss_root_hints} PATH_SUFFIXES "include" "inc")

    if(_gss_INCLUDE_DIRS)  # We have found something
      set(_gss_libdir_suffixes "")

      cmake_push_check_state()
      list(APPEND CMAKE_REQUIRED_INCLUDES "${_gss_INCLUDE_DIRS}")
      check_include_files("gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" _gss_have_mit_headers)
      cmake_pop_check_state()

      if(_gss_have_mit_headers)
        set(_gss_flavour "MIT")
        if(WIN32)
          if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            list(APPEND _gss_libdir_suffixes "lib/AMD64")
            set(_gss_libname "gssapi64")
          else()
            list(APPEND _gss_libdir_suffixes "lib/i386")
            set(_gss_libname "gssapi32")
          endif()
        else()
          list(APPEND _gss_libdir_suffixes "lib" "lib64")  # those suffixes are not checked for HINTS
          set(_gss_libname "gssapi_krb5")
        endif()
      endif()
    else()
      find_path(_gss_INCLUDE_DIRS NAMES "gss.h" HINTS ${_gss_root_hints} PATH_SUFFIXES "include")

      if(_gss_INCLUDE_DIRS)
        set(_gss_flavour "GNU")
        set(_gss_pc_requires ${_gnu_modname})
        set(_gss_libname "gss")
      endif()
    endif()

    # If we have headers, look up libraries
    if(_gss_flavour)
      set(_gss_libdir_hints ${_gss_root_hints})
      if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.20)
        cmake_path(GET _gss_INCLUDE_DIRS PARENT_PATH _gss_calculated_potential_root)
      else()
        get_filename_component(_gss_calculated_potential_root "${_gss_INCLUDE_DIRS}" DIRECTORY)
      endif()
      list(APPEND _gss_libdir_hints ${_gss_calculated_potential_root})

      find_library(_gss_LIBRARIES NAMES ${_gss_libname} HINTS ${_gss_libdir_hints} PATH_SUFFIXES ${_gss_libdir_suffixes})
    endif()
  endif()
  if(NOT _gss_flavour)
    message(FATAL_ERROR "GNU or MIT GSS is required")
  endif()
else()
  # _gss_MODULE_NAME set since CMake 3.16.
  # _pkg_check_modules_pkg_name is undocumented and used as a fallback for CMake <3.16 versions.
  if(_gss_MODULE_NAME STREQUAL _gnu_modname OR _pkg_check_modules_pkg_name STREQUAL _gnu_modname)
    set(_gss_flavour "GNU")
    set(_gss_pc_requires ${_gnu_modname})
  elseif(_gss_MODULE_NAME STREQUAL _mit_modname OR _pkg_check_modules_pkg_name STREQUAL _mit_modname)
    set(_gss_flavour "MIT")
    set(_gss_pc_requires ${_mit_modname})
  else()
    message(FATAL_ERROR "GNU or MIT GSS is required")
  endif()
  message(STATUS "Found GSS/${_gss_flavour} (via pkg-config): ${_gss_INCLUDE_DIRS} (found version \"${_gss_version}\")")
endif()

set(GSS_VERSION ${_gss_version})

if(NOT GSS_VERSION)
  if(_gss_flavour STREQUAL "MIT")
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
      cmake_host_system_information(RESULT _mit_version QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/MIT/Kerberos/SDK/CurrentVersion" VALUE "VersionString")
    else()
      get_filename_component(_mit_version
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos\\SDK\\CurrentVersion;VersionString]" NAME CACHE)
    endif()
    if(WIN32 AND _mit_version)
      set(GSS_VERSION "${_mit_version}")
    else()
      set(GSS_VERSION "MIT Unknown")
    endif()
  else()  # GNU
    if(_gss_INCLUDE_DIRS AND EXISTS "${_gss_INCLUDE_DIRS}/gss.h")
      set(_version_regex "#[\t ]*define[\t ]+GSS_VERSION[\t ]+\"([^\"]*)\"")
      file(STRINGS "${_gss_INCLUDE_DIRS}/gss.h" _version_str REGEX "${_version_regex}")
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
    _gss_flavour
    _gss_LIBRARIES
  VERSION_VAR
    GSS_VERSION
  FAIL_MESSAGE
    "Could NOT find GSS, try to set the absolute path to GSS installation root directory in the environment variable GSS_ROOT_DIR"
)

mark_as_advanced(
  _gss_CFLAGS
  _gss_FOUND
  _gss_INCLUDE_DIRS
  _gss_LIBRARIES
  _gss_LIBRARY_DIRS
  _gss_MODULE_NAME
  _gss_PREFIX
  _gss_version
)

if(GSS_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_gss_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::gss)
    add_library(CURL::gss INTERFACE IMPORTED)
    set_target_properties(CURL::gss PROPERTIES
      INTERFACE_CURL_GSS_FLAVOUR "${_gss_flavour}"
      INTERFACE_LIBCURL_PC_MODULES "${_gss_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_gss_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_gss_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_gss_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_gss_LIBRARIES}")
  endif()
endif()
