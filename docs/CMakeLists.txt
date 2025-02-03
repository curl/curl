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

if(BUILD_LIBFETCH_DOCS)
  add_subdirectory(libfetch)
endif()
if(ENABLE_FETCH_MANUAL AND BUILD_FETCH_EXE)
  add_subdirectory(cmdline-opts)
endif()

if(BUILD_MISC_DOCS)
  foreach(_man_misc IN ITEMS "fetch-config" "mk-ca-bundle")
    set(_man_target "${CMAKE_CURRENT_BINARY_DIR}/${_man_misc}.1")
    add_custom_command(OUTPUT "${_man_target}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/cd2nroff" "${_man_misc}.md" > "${_man_target}"
      DEPENDS "${_man_misc}.md"
      VERBATIM
    )
    add_custom_target("fetch-generate-${_man_misc}.1" ALL DEPENDS "${_man_target}")
    if(NOT FETCH_DISABLE_INSTALL)
      install(FILES "${_man_target}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
    endif()
  endforeach()
endif()
