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
macro(check_include_file_concat _file _variable)
  check_include_files("${CURL_INCLUDES};${_file}" ${_variable})
  if(${_variable})
    set(CURL_INCLUDES ${CURL_INCLUDES} ${_file})
    set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -D${_variable}")
  endif()
endmacro()

# For other curl specific tests, use this macro.
# Return result in variable: CURL_TEST_OUTPUT
macro(curl_internal_test _curl_test)
  if(NOT DEFINED "${_curl_test}")
    set(_macro_check_function_definitions
      "-D${_curl_test} ${CURL_TEST_DEFINES} ${CMAKE_REQUIRED_FLAGS}")
    if(CMAKE_REQUIRED_LIBRARIES)
      set(_curl_test_add_libraries
        "-DLINK_LIBRARIES:STRING=${CMAKE_REQUIRED_LIBRARIES}")
    endif()

    message(STATUS "Performing Test ${_curl_test}")
    try_compile(${_curl_test}
      ${CMAKE_BINARY_DIR}
      "${CMAKE_CURRENT_SOURCE_DIR}/CMake/CurlTests.c"
      CMAKE_FLAGS
        "-DCOMPILE_DEFINITIONS:STRING=${_macro_check_function_definitions}"
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

macro(optional_dependency _dependency)
  set(CURL_${_dependency} "AUTO" CACHE STRING "Build curl with ${_dependency} support (AUTO, ON or OFF)")
  set_property(CACHE CURL_${_dependency} PROPERTY STRINGS "AUTO" "ON" "OFF")

  if(CURL_${_dependency} STREQUAL "AUTO")
    find_package(${_dependency})
  elseif(CURL_${_dependency})
    find_package(${_dependency} REQUIRED)
  endif()
endmacro()
