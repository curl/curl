#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats, et al.
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

option(CURL_COMPLETION_FISH "Install fish completions" OFF)
option(CURL_COMPLETION_ZSH "Install zsh completions" OFF)

if(CURL_COMPLETION_FISH OR
   CURL_COMPLETION_ZSH)
  if(PERL_FOUND)
    if(CURL_COMPLETION_FISH)
      set(_completion_fish "${CMAKE_CURRENT_BINARY_DIR}/curl.fish")
      add_custom_command(OUTPUT "${_completion_fish}"
        COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/completion.pl"
          --opts-dir "${PROJECT_SOURCE_DIR}/docs/cmdline-opts" --shell fish > "${_completion_fish}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/completion.pl"
        VERBATIM
      )
      add_custom_target("curl-completion-fish" ALL DEPENDS "${_completion_fish}")
    endif()

    if(CURL_COMPLETION_ZSH)
      set(_completion_zsh "${CMAKE_CURRENT_BINARY_DIR}/_curl")
      add_custom_command(OUTPUT "${_completion_zsh}"
        COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/completion.pl"
          --opts-dir "${PROJECT_SOURCE_DIR}/docs/cmdline-opts" --shell zsh > "${_completion_zsh}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/completion.pl"
        VERBATIM
      )
      add_custom_target("curl-completion-zsh" ALL DEPENDS "${_completion_zsh}")
    endif()

    if(NOT CURL_DISABLE_INSTALL)
      if(CURL_COMPLETION_FISH)
        if(NOT CURL_COMPLETION_FISH_DIR AND NOT CMAKE_CROSSCOMPILING AND NOT DEFINED CMAKE_INSTALL_PREFIX)
          find_package(PkgConfig QUIET)
          pkg_get_variable(CURL_COMPLETION_FISH_DIR "fish" "completionsdir")
        endif()
        if(NOT CURL_COMPLETION_FISH_DIR AND CMAKE_INSTALL_DATAROOTDIR)
          set(CURL_COMPLETION_FISH_DIR "${CMAKE_INSTALL_DATAROOTDIR}/fish/vendor_completions.d")
        endif()
        if(CURL_COMPLETION_FISH_DIR)
          install(FILES "${_completion_fish}" DESTINATION "${CURL_COMPLETION_FISH_DIR}")
        endif()
      endif()
      if(CURL_COMPLETION_ZSH)
        if(NOT CURL_COMPLETION_ZSH_DIR AND CMAKE_INSTALL_DATAROOTDIR)
          set(CURL_COMPLETION_ZSH_DIR "${CMAKE_INSTALL_DATAROOTDIR}/zsh/site-functions")
        endif()
        if(CURL_COMPLETION_ZSH_DIR)
          install(FILES "${_completion_zsh}" DESTINATION "${CURL_COMPLETION_ZSH_DIR}")
        endif()
      endif()
    endif()
  else()
    message(WARNING "No perl: cannot generate completion script")
  endif()
endif()
