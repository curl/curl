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
add_custom_target(curl-examples)

# Get check_PROGRAMS, COMPLICATED_MAY_BUILD, COMPLICATED_EXAMPLES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set(_with_deps "")
set(_all_src "")
set(_all_canary "")
set(_all "all")
foreach(_target IN LISTS COMPLICATED_MAY_BUILD check_PROGRAMS _all)  # keep 'COMPLICATED_MAY_BUILD' first, and '_all' last
  # Strip .c suffix from COMPLICATED_MAY_BUILD items
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.20)
    cmake_path(GET _target STEM _target)
  else()
    get_filename_component(_target "${_target}" NAME_WE)
  endif()
  set(_more_libs "")
  set(_target_name "curl-example-${_target}")
  if(_target STREQUAL "all")
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
      add_library(${_target_name} OBJECT EXCLUDE_FROM_ALL ${_all_src})
      if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")  # MSVC but exclude clang-cl
        # CMake generates a static library for the OBJECT target. Silence these 'lib.exe' warnings:
        # warning LNK4006: main already defined in ....obj; second definition ignored
        # warning LNK4221: This object file does not define any previously undefined public symbols,
        #                  so it will not be used by any link operation that consumes this library
        if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
          set_target_properties(${_target_name} PROPERTIES STATIC_LIBRARY_OPTIONS "-ignore:4006;-ignore:4221")
        else()
          set_target_properties(${_target_name} PROPERTIES STATIC_LIBRARY_FLAGS "-ignore:4006 -ignore:4221")
        endif()
      endif()
    else()
      add_library(${_target_name} STATIC EXCLUDE_FROM_ALL ${_all_src})
    endif()
    if(_with_deps)
      set(_more_libs ${CURL_LIBS})  # If any examples required dependencies, link them
    endif()
    add_custom_target(curl-examples-build)  # Special target to compile all tests quickly and build a single test to probe linkage
    add_dependencies(curl-examples-build ${_target_name} ${_all_canary})  # Include a full build of a single test
  else()
    # Check if the example requires a build option. Then check if that build option is enabled.
    # If it is, link all dependencies to the example.
    set(_requires_regex "/\\* Requires: ([A-Z0-9_]+) \\*/")
    file(STRINGS "${_target}.c" _req REGEX "${_requires_regex}")
    string(REGEX REPLACE "${_requires_regex}" "\\1" _req "${_req}")
    if(_req)
      if(${${_req}})
        string(APPEND _with_deps " ${_target}:${_req}")
        set(_more_libs ${CURL_LIBS})
      else()
        continue()  # Option required, but not found
      endif()
    endif()
    set(_all_canary ${_target_name})  # Save the last test for the curl-examples-build target
    list(APPEND _all_src "${_target}.c")
    add_executable(${_target_name} EXCLUDE_FROM_ALL "${_target}.c")
    add_dependencies(curl-examples ${_target_name})
  endif()
  target_link_libraries(${_target_name} ${LIB_SELECTED} ${CURL_NETWORK_AND_TIME_LIBS} ${_more_libs})
  target_compile_definitions(${_target_name} PRIVATE "CURL_NO_OLDIES" "$<$<BOOL:${WIN32}>:WIN32_LEAN_AND_MEAN>")
  set_target_properties(${_target_name} PROPERTIES OUTPUT_NAME "${_target}" PROJECT_LABEL "Example ${_target}" UNITY_BUILD OFF)
endforeach()

if(_with_deps)
  message(STATUS "Enabled examples with dependencies:${_with_deps}")
endif()

if(CURL_BUILD_EVERYTHING STREQUAL "QUICK")
  set_target_properties(curl-examples-build PROPERTIES EXCLUDE_FROM_ALL FALSE)
elseif(CURL_BUILD_EVERYTHING AND NOT CURL_BUILD_EVERYTHING STREQUAL "NOEXAMPLES")
  set_target_properties(curl-examples PROPERTIES EXCLUDE_FROM_ALL FALSE)
endif()
