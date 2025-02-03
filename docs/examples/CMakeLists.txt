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

add_custom_target(fetch-examples)

# Get 'check_PROGRAMS' variable
fetch_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

foreach(_target IN LISTS check_PROGRAMS)
  set(_target_name "fetch-example-${_target}")
  add_executable(${_target_name} EXCLUDE_FROM_ALL "${_target}.c")
  add_dependencies(fetch-examples ${_target_name})
  target_link_libraries(${_target_name} ${LIB_SELECTED} ${FETCH_LIBS})
  target_compile_definitions(${_target_name} PRIVATE "FETCH_NO_OLDIES" "$<$<BOOL:MSVC>:_CRT_SECURE_NO_DEPRECATE>")
  if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
    set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS "FETCH_STATICLIB")
  endif()
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}" UNITY_BUILD OFF
    PROJECT_LABEL "Example ${_target}")
endforeach()
