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

cmake_minimum_required(VERSION 3.7...3.16 FATAL_ERROR)
message(STATUS "Using CMake version ${CMAKE_VERSION}")

project(test-consumer C)

option(TEST_INTEGRATION_MODE "Integration mode" "find_package")

message(STATUS "TEST_INTEGRATION_MODE: ${TEST_INTEGRATION_MODE}")

if(TEST_INTEGRATION_MODE STREQUAL "FetchContent" AND CMAKE_VERSION VERSION_LESS 3.14)
  message(FATAL_ERROR "This test requires CMake 3.14 or upper")
endif()

if(TEST_INTEGRATION_MODE STREQUAL "ExternalProject")  # Broken
  include(ExternalProject)
  ExternalProject_Add(libssh2
    URL "${FROM_ARCHIVE}" URL_HASH "SHA256=${FROM_HASH}"
    INSTALL_COMMAND ""
    DOWNLOAD_EXTRACT_TIMESTAMP ON)
endif()

if(TEST_INTEGRATION_MODE STREQUAL "find_package" OR
   TEST_INTEGRATION_MODE STREQUAL "ExternalProject")
  find_package(CURL REQUIRED CONFIG)
  find_package(CURL REQUIRED CONFIG)  # Double-inclusion test
  foreach(result_var IN ITEMS
      CURL_FOUND
      CURL_SUPPORTS_HTTPS
      CURL_SUPPORTS_Largefile
      CURL_VERSION
      CURL_VERSION_STRING
    )
    if(NOT ${result_var})
      message(FATAL_ERROR "'${result_var}' variable expected, but not set by the CURL package.")
    endif()
  endforeach()
  # Show variables set by find_package()
  get_cmake_property(_vars VARIABLES)
  foreach(_var IN ITEMS ${_vars})
    string(TOUPPER "${_var}" _var_upper)
    if(_var_upper MATCHES "CURL")
      get_property(_var_type CACHE ${_var} PROPERTY TYPE)
      if(_var_type)
        set(_var_type ":${_var_type}")
      endif()
      message("find_package() sets: ${_var}${_var_type} = '${${_var}}'")
    endif()
  endforeach()
elseif(TEST_INTEGRATION_MODE STREQUAL "add_subdirectory")
  set(BUILD_SHARED_LIBS ON CACHE BOOL "")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "")
  add_subdirectory(curl)
elseif(TEST_INTEGRATION_MODE STREQUAL "FetchContent")
  include(FetchContent)
  option(FROM_GIT_REPO "Git URL" "https://github.com/curl/curl.git")
  option(FROM_GIT_TAG "Git tag" "master")
  FetchContent_Declare(curl
    GIT_REPOSITORY "${FROM_GIT_REPO}"
    GIT_TAG "${FROM_GIT_TAG}"
    GIT_SHALLOW)
  set(BUILD_SHARED_LIBS ON CACHE BOOL "")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "")
  FetchContent_MakeAvailable(curl)  # Requires CMake 3.14
endif()

add_executable(test-consumer-static-ns "test.c")
target_link_libraries(test-consumer-static-ns PRIVATE "CURL::libcurl_static")

add_executable(test-consumer-shared-ns "test.c")
target_link_libraries(test-consumer-shared-ns PRIVATE "CURL::libcurl_shared")

# Alias for either shared or static library
add_executable(test-consumer-selected-ns "test.c")
target_link_libraries(test-consumer-selected-ns PRIVATE "CURL::libcurl")

if(TEST_INTEGRATION_MODE STREQUAL "add_subdirectory" OR
   TEST_INTEGRATION_MODE STREQUAL "FetchContent")

  add_executable(test-consumer-static-bare "test.c")
  target_link_libraries(test-consumer-static-bare PRIVATE "libcurl_static")

  add_executable(test-consumer-shared-bare "test.c")
  target_link_libraries(test-consumer-shared-bare PRIVATE "libcurl_shared")

  add_executable(test-consumer-selected-bare "test.c")
  target_link_libraries(test-consumer-selected-bare PRIVATE "libcurl")
endif()
