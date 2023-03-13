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
set(LIB_NAME libcurl)
set(LIBCURL_OUTPUT_NAME libcurl CACHE STRING "Basename of the curl library")
add_definitions(-DBUILDING_LIBCURL)

if(BUILD_SHARED_LIBS)
  set(CURL_STATICLIB NO)
else()
  set(CURL_STATICLIB YES)
endif()

# Use:
# * CURL_STATICLIB
configure_file(curl_config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h)

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

list(APPEND HHEADERS
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h
  )

if(WIN32 AND NOT CURL_STATICLIB)
  list(APPEND CSOURCES libcurl.rc)
endif()

# The rest of the build

include_directories(${CMAKE_CURRENT_BINARY_DIR}/../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
if(USE_ARES)
  include_directories(${CARES_INCLUDE_DIR})
endif()

add_library(
  ${LIB_NAME}
  ${HHEADERS} ${CSOURCES}
  )

add_library(
  ${PROJECT_NAME}::${LIB_NAME}
  ALIAS ${LIB_NAME}
  )

if(NOT BUILD_SHARED_LIBS)
    set_target_properties(${LIB_NAME} PROPERTIES INTERFACE_COMPILE_DEFINITIONS CURL_STATICLIB)
endif()

target_link_libraries(${LIB_NAME} PRIVATE ${CURL_LIBS})

transform_makefile_inc("Makefile.soname" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake)

set_target_properties(${LIB_NAME} PROPERTIES
  COMPILE_DEFINITIONS BUILDING_LIBCURL
  OUTPUT_NAME ${LIBCURL_OUTPUT_NAME}
  )

if(CMAKE_SYSTEM_NAME STREQUAL "AIX" OR
  CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
  CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
  CMAKE_SYSTEM_NAME STREQUAL "GNU/kFreeBSD" OR

  # FreeBSD comes with the a.out and elf flavours
  # but a.out was supported up to version 3.x and
  # elf from 3.x. I cannot imagine someone running
  # CMake on those ancient systems
  CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR

  CMAKE_SYSTEM_NAME STREQUAL "Haiku")

  math(EXPR CMAKESONAME "${VERSIONCHANGE} - ${VERSIONDEL}")
  set(CMAKEVERSION "${CMAKESONAME}.${VERSIONDEL}.${VERSIONADD}")

  set_target_properties(${LIB_NAME} PROPERTIES
    VERSION ${CMAKEVERSION}
    SOVERSION ${CMAKESONAME}
  )

endif()


if(HIDES_CURL_PRIVATE_SYMBOLS)
  set_property(TARGET ${LIB_NAME} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  set_property(TARGET ${LIB_NAME} APPEND PROPERTY COMPILE_FLAGS ${CURL_CFLAG_SYMBOLS_HIDE})
endif()

# Remove the "lib" prefix since the library is already named "libcurl".
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
set_target_properties(${LIB_NAME} PROPERTIES IMPORT_PREFIX "")

if(CURL_HAS_LTO)
  set_target_properties(${LIB_NAME} PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
endif()

if(WIN32)
  if(BUILD_SHARED_LIBS)
    if(MSVC)
      # Add "_imp" as a suffix before the extension to avoid conflicting with
      # the statically linked "libcurl.lib"
      set_target_properties(${LIB_NAME} PROPERTIES IMPORT_SUFFIX "_imp.lib")
    endif()
  endif()
endif()

target_include_directories(${LIB_NAME} INTERFACE
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${CURL_SOURCE_DIR}/include>)

if(CURL_ENABLE_EXPORT_TARGET)
  install(TARGETS ${LIB_NAME}
    EXPORT ${TARGETS_EXPORT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )

  export(TARGETS ${LIB_NAME}
         FILE ${PROJECT_BINARY_DIR}/libcurl-target.cmake
         NAMESPACE ${PROJECT_NAME}::
  )
endif()
