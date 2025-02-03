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

# Get 'UNITPROGS', '*_SOURCES', 'FIRSTFILES' variables
fetch_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

if(FETCH_TEST_BUNDLES)
  add_custom_command(
    OUTPUT "unit_bundle.c"
    COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" "${CMAKE_CURRENT_SOURCE_DIR}" > "unit_bundle.c"
    DEPENDS
      "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${FIRSTFILES}
      "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    VERBATIM)

  set(UNITPROGS "units")
  set(units_SOURCES "unit_bundle.c")
endif()

foreach(_target IN LISTS UNITPROGS)
  set(_target_name "${_target}")
  add_executable(${_target_name} EXCLUDE_FROM_ALL ${${_target}_SOURCES})
  add_dependencies(testdeps ${_target_name})
  target_link_libraries(${_target_name} fetchtool fetchu)
  target_include_directories(${_target_name} PRIVATE
    "${PROJECT_BINARY_DIR}/lib"            # for "fetch_config.h"
    "${PROJECT_SOURCE_DIR}/lib"            # for "fetch_setup.h"
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/tests/libtest"
  )
  if(FETCH_TEST_BUNDLES)
    target_include_directories(${_target_name} PRIVATE "${PROJECT_SOURCE_DIR}/tests/unit")
  endif()
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}"
    PROJECT_LABEL "Test unit ${_target}")
endforeach()
