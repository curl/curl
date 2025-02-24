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
# File defines convenience macros for available feature testing

# Check if header file exists and add it to the list.
# This macro is intended to be called multiple times with a sequence of
# possibly dependent header files.  Some headers depend on others to be
# compiled correctly.
macro(check_include_file_concat_curl _file _variable)
  check_include_files("${CURL_INCLUDES};${_file}" ${_variable})
  if(${_variable})
    list(APPEND CURL_INCLUDES ${_file})
  endif()
endmacro()

set(CURL_TEST_DEFINES "")  # Initialize global variable

# For other curl specific tests, use this macro.
# Return result in variable: CURL_TEST_OUTPUT
macro(curl_internal_test _curl_test)
  if(NOT DEFINED "${_curl_test}")
    string(REPLACE ";" " " _cmake_required_definitions "${CMAKE_REQUIRED_DEFINITIONS}")
    set(_curl_test_add_libraries "")
    if(CMAKE_REQUIRED_LIBRARIES)
      set(_curl_test_add_libraries
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    endif()

    message(STATUS "Performing Test ${_curl_test}")
    try_compile(${_curl_test}
      ${PROJECT_BINARY_DIR}
      "${CMAKE_CURRENT_SOURCE_DIR}/CMake/CurlTests.c"
      CMAKE_FLAGS
        "-DCOMPILE_DEFINITIONS:STRING=-D${_curl_test} ${CURL_TEST_DEFINES} ${_cmake_required_definitions}"
        "${_curl_test_add_libraries}"
      OUTPUT_VARIABLE CURL_TEST_OUTPUT)
    if(${_curl_test})
      set(${_curl_test} 1 CACHE INTERNAL "Curl test")
      message(STATUS "Performing Test ${_curl_test} - Success")
    else()
      set(${_curl_test} "" CACHE INTERNAL "Curl test")
      message(STATUS "Performing Test ${_curl_test} - Failed")
    endif()
  endif()
endmacro()

macro(curl_dependency_option _option_name _find_name _desc_name)
  set(${_option_name} "AUTO" CACHE STRING "Build curl with ${_desc_name} support (AUTO, ON or OFF)")
  set_property(CACHE ${_option_name} PROPERTY STRINGS "AUTO" "ON" "OFF")

  if(${_option_name} STREQUAL "AUTO")
    find_package(${_find_name})
  elseif(${_option_name})
    find_package(${_find_name} REQUIRED)
  endif()
endmacro()

# Convert the passed paths to libpath linker options and add them to CMAKE_REQUIRED_*.
macro(curl_required_libpaths _libpaths_arg)
  if(CMAKE_VERSION VERSION_LESS 3.31)
    set(_libpaths "${_libpaths_arg}")
    foreach(_libpath IN LISTS _libpaths)
      list(APPEND CMAKE_REQUIRED_LINK_OPTIONS "${CMAKE_LIBRARY_PATH_FLAG}${_libpath}")
    endforeach()
  else()
    list(APPEND CMAKE_REQUIRED_LINK_DIRECTORIES "${_libpaths_arg}")
  endif()
endmacro()

# Pre-fill variables set by a check_type_size() call.
macro(curl_prefill_type_size _type _size)
  set(HAVE_SIZEOF_${_type} TRUE)
  set(SIZEOF_${_type} ${_size})
  set(SIZEOF_${_type}_CODE "#define SIZEOF_${_type} ${_size}")
endmacro()
