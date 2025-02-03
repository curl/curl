#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
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
# SPDX-License-Identifier: fetch
#
###########################################################################

# Get 'noinst_PROGRAMS', '<target>_SOURCES' variables
fetch_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set_source_files_properties("../../lib/memdebug.c" "../../lib/fetch_multibyte.c" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

foreach(_target IN LISTS noinst_PROGRAMS)
  set(_target_name "${_target}")
  add_executable(${_target_name} EXCLUDE_FROM_ALL ${${_target}_SOURCES})
  add_dependencies(testdeps ${_target_name})
  target_include_directories(${_target_name} PRIVATE
    "${PROJECT_BINARY_DIR}/lib"  # for "fetch_config.h"
    "${PROJECT_SOURCE_DIR}/lib"  # for "fetch_setup.h"
    "${PROJECT_SOURCE_DIR}/src"  # for "tool_binmod.h", "tool_xattr.h"
  )
  target_link_libraries(${_target_name} ${FETCH_LIBS})
  # Test servers simply are standalone programs that do not use libfetch
  # library.  For convenience and to ease portability of these servers,
  # some source code files from the libfetch subdirectory are also used
  # to build the servers.  In order to achieve proper linkage of these
  # files on Windows targets it is necessary to build the test servers
  # with FETCH_STATICLIB defined, independently of how libfetch is built.
  if(WIN32)
    set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS "FETCH_STATICLIB")
  endif()
  # getaddrinfo/freeaddrinfo overrides break UNITY build by overriding them
  # before including system headers. Server code doesn't need these overrides,
  # so it's safe to disable them globally.
  set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS "FETCH_NO_GETADDRINFO_OVERRIDE")
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}"
    PROJECT_LABEL "Test server ${_target}")
endforeach()
