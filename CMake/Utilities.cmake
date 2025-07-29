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
# File containing various utilities

# Return number of arguments that evaluate to true
function(curl_count_true _output_count_var)
  set(_list_len 0)
  foreach(_option_var IN LISTS ARGN)
    if(${_option_var})
      math(EXPR _list_len "${_list_len} + 1")
    endif()
  endforeach()
  set(${_output_count_var} ${_list_len} PARENT_SCOPE)
endfunction()

# Dump all defined variables with their values
function(curl_dumpvars)
  message("::group::CMake Variable Dump")
  get_cmake_property(_vars VARIABLES)
  foreach(_var IN ITEMS ${_vars})
    get_property(_var_type CACHE ${_var} PROPERTY TYPE)
    get_property(_var_advanced CACHE ${_var} PROPERTY ADVANCED)
    if(_var_type)
      set(_var_type ":${_var_type}")
    endif()
    if(_var_advanced)
      set(_var_advanced " [adv]")
    endif()
    message("${_var}${_var_type}${_var_advanced} = '${${_var}}'")
  endforeach()
  message("::endgroup::")
endfunction()

# Dump all target properties
function(curl_dumptargetprops _target)
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.19 AND TARGET "${_target}")
    execute_process(COMMAND "${CMAKE_COMMAND}" "--help-property-list" OUTPUT_VARIABLE _cmake_property_list)
    string(REPLACE "\n" ";" _cmake_property_list "${_cmake_property_list}")
    list(REMOVE_DUPLICATES _cmake_property_list)
    list(REMOVE_ITEM _cmake_property_list "")
    foreach(_prop IN LISTS _cmake_property_list)
      if(_prop MATCHES "<CONFIG>")
        foreach(_config IN ITEMS "DEBUG" "RELEASE" "MINSIZEREL" "RELWITHDEBINFO")
          string(REPLACE "<CONFIG>" "${_config}" _propconfig "${_prop}")
          get_property(_is_set TARGET "${_target}" PROPERTY "${_propconfig}" SET)
          if(_is_set)
            get_target_property(_val "${_target}" "${_propconfig}")
            message("${_target}.${_propconfig} = '${_val}'")
          endif()
        endforeach()
      else()
        get_property(_is_set TARGET "${_target}" PROPERTY "${_prop}" SET)
        if(_is_set)
          get_target_property(_val "${_target}" "${_prop}")
          message("${_target}.${_prop} = '${_val}'")
        endif()
      endif()
    endforeach()
  endif()
endfunction()
