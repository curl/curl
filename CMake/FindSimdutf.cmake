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
# Find the simdutf library and its Base64 C API
#
# Input variables:
#
# - `SIMDUTF_INCLUDE_DIR`:  Absolute path to simdutf include directory.
# - `SIMDUTF_LIBRARY`:      Absolute path to `simdutf` library.
#
# Defines:
#
# - `SIMDUTF_FOUND`:        System has simdutf with its Base64 C API.
# - `SIMDUTF_VERSION`:      Version of simdutf.
# - `CURL::simdutf`:        simdutf library target.

set(_simdutf_pc_requires "simdutf")
set(_simdutf_from_pkgconfig OFF)
set(_simdutf_from_config OFF)
set(_simdutf_CFLAGS "")
set(_simdutf_INCLUDE_DIRS "")
set(_simdutf_LIBRARY_DIRS "")
set(_simdutf_LIBRARIES "")
set(SIMDUTF_VERSION "")

if(NOT DEFINED SIMDUTF_INCLUDE_DIR AND NOT DEFINED SIMDUTF_LIBRARY)
  if(CURL_USE_PKGCONFIG)
    find_package(PkgConfig QUIET)
    pkg_check_modules(_simdutf_pc ${_simdutf_pc_requires})
    set(_simdutf_from_pkgconfig "${_simdutf_pc_FOUND}")
  endif()
  if(NOT _simdutf_from_pkgconfig AND CURL_USE_CMAKECONFIG)
    # Upstream's SameMinorVersion policy rejects newer minor/major releases
    # for a versioned request. Check the minimum version ourselves below.
    find_package(simdutf CONFIG QUIET)
    if(simdutf_CONFIG AND TARGET simdutf::simdutf)
      set(_simdutf_from_config ON)
    endif()
  endif()
endif()

if(_simdutf_from_pkgconfig)
  set(SIMDUTF_VERSION "${_simdutf_pc_VERSION}")
  set(_simdutf_CFLAGS       "${_simdutf_pc_CFLAGS}")
  set(_simdutf_INCLUDE_DIRS "${_simdutf_pc_INCLUDE_DIRS}")
  set(_simdutf_LIBRARY_DIRS "${_simdutf_pc_LIBRARY_DIRS}")
  set(_simdutf_LIBRARIES    "${_simdutf_pc_LIBRARIES}")
elseif(_simdutf_from_config)
  set(SIMDUTF_VERSION "${simdutf_VERSION}")
  set(_simdutf_LIBRARIES simdutf::simdutf)
else()
  find_path(SIMDUTF_INCLUDE_DIR NAMES "simdutf_c.h")
  find_library(SIMDUTF_LIBRARY NAMES "simdutf")
  if(SIMDUTF_INCLUDE_DIR AND EXISTS "${SIMDUTF_INCLUDE_DIR}/simdutf/simdutf_version.h")
    file(STRINGS "${SIMDUTF_INCLUDE_DIR}/simdutf/simdutf_version.h" _simdutf_version_line
      REGEX "^#define SIMDUTF_VERSION ")
    string(REGEX REPLACE "^#define SIMDUTF_VERSION \"([^\"]*)\".*" "\\1"
      SIMDUTF_VERSION "${_simdutf_version_line}")
  endif()
  if(SIMDUTF_INCLUDE_DIR AND SIMDUTF_LIBRARY)
    set(_simdutf_INCLUDE_DIRS "${SIMDUTF_INCLUDE_DIR}")
    set(_simdutf_LIBRARIES "${SIMDUTF_LIBRARY}")
  endif()
  mark_as_advanced(SIMDUTF_INCLUDE_DIR SIMDUTF_LIBRARY)
endif()

if(_simdutf_LIBRARIES AND SIMDUTF_VERSION VERSION_GREATER_EQUAL Simdutf_FIND_VERSION)
  if(NOT TARGET CURL::simdutf)
    add_library(CURL::simdutf INTERFACE IMPORTED)
    set_target_properties(CURL::simdutf PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_simdutf_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_simdutf_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_simdutf_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_simdutf_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_simdutf_LIBRARIES}")
  endif()

  include(CMakePushCheckState)
  include(CheckCSourceCompiles)
  include(CheckCXXSourceCompiles)
  # Recheck when an existing build changes its simdutf installation or linkage.
  unset(SIMDUTF_HAS_C_API CACHE)
  unset(SIMDUTF_HAS_C_API_WITH_RUNTIME CACHE)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES CURL::simdutf)
  set(_simdutf_test "
    #include <simdutf_c.h>
    int main(void)
    {
      char output[8];
      simdutf_result result;
      (void)simdutf_binary_to_base64(\"abc\", 3, output, SIMDUTF_BASE64_DEFAULT);
      result = simdutf_base64_to_binary(\"YWJj\", 4, output,
        SIMDUTF_BASE64_DEFAULT, SIMDUTF_LAST_CHUNK_LOOSE);
      return (int)result.error;
    }")
  if(CMAKE_C_COMPILER_LOADED)
    check_c_source_compiles("${_simdutf_test}" SIMDUTF_HAS_C_API)
  else()
    check_cxx_source_compiles("${_simdutf_test}" SIMDUTF_HAS_C_API)
  endif()
  set(_simdutf_c_api "${SIMDUTF_HAS_C_API}")

  if(NOT _simdutf_c_api)
    # Static simdutf may omit its C++ runtime from the dependency metadata.
    # Discover it from the toolchain instead of assuming libstdc++ or libc++.
    include(CheckLanguage)
    check_language(CXX)
    if(CMAKE_CXX_COMPILER)
      enable_language(CXX)
      set(_simdutf_runtime "${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES}")
      set(_simdutf_runtime_dirs "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
      if(CMAKE_C_IMPLICIT_LINK_LIBRARIES)
        list(REMOVE_ITEM _simdutf_runtime ${CMAKE_C_IMPLICIT_LINK_LIBRARIES})
      endif()
      if(CMAKE_C_IMPLICIT_LINK_DIRECTORIES)
        list(REMOVE_ITEM _simdutf_runtime_dirs ${CMAKE_C_IMPLICIT_LINK_DIRECTORIES})
      endif()
      set_property(TARGET CURL::simdutf APPEND PROPERTY INTERFACE_LINK_LIBRARIES "${_simdutf_runtime}")
      set_property(TARGET CURL::simdutf APPEND PROPERTY INTERFACE_LINK_DIRECTORIES "${_simdutf_runtime_dirs}")
      if(CMAKE_C_COMPILER_LOADED)
        check_c_source_compiles("${_simdutf_test}" SIMDUTF_HAS_C_API_WITH_RUNTIME)
      else()
        check_cxx_source_compiles("${_simdutf_test}" SIMDUTF_HAS_C_API_WITH_RUNTIME)
      endif()
      set(_simdutf_c_api "${SIMDUTF_HAS_C_API_WITH_RUNTIME}")
    endif()
  endif()
  cmake_pop_check_state()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Simdutf
  REQUIRED_VARS
    _simdutf_LIBRARIES
    _simdutf_c_api
  VERSION_VAR
    SIMDUTF_VERSION
  REASON_FAILURE_MESSAGE "simdutf must provide the Base64 C API. Static builds may also require a C++ compiler."
)
