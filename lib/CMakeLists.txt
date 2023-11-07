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

configure_file(curl_config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h)

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

list(APPEND HHEADERS
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h
  )

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

if(BUILD_TESTING)
  add_library(
    curlu # special libcurlu library just for unittests
    STATIC
    EXCLUDE_FROM_ALL
    ${HHEADERS} ${CSOURCES}
  )
  target_compile_definitions(curlu PUBLIC UNITTESTS CURL_STATICLIB)
endif()

if(ENABLE_CURLDEBUG)
  # We must compile these sources separately to avoid memdebug.h redefinitions
  # applying to them.
  set_source_files_properties(memdebug.c curl_multibyte.c PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
endif()

if(BUILD_TESTING)
  target_link_libraries(curlu PRIVATE ${CURL_LIBS})
endif()

transform_makefile_inc("Makefile.soname" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake)

if(CMAKE_SYSTEM_NAME STREQUAL "AIX" OR
  CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
  CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
  CMAKE_SYSTEM_NAME STREQUAL "SunOS" OR
  CMAKE_SYSTEM_NAME STREQUAL "GNU/kFreeBSD" OR

  # FreeBSD comes with the a.out and elf flavours
  # but a.out was supported up to version 3.x and
  # elf from 3.x. I cannot imagine someone running
  # CMake on those ancient systems
  CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR

  CMAKE_SYSTEM_NAME STREQUAL "Haiku")

  math(EXPR CMAKESONAME "${VERSIONCHANGE} - ${VERSIONDEL}")
  set(CMAKEVERSION "${CMAKESONAME}.${VERSIONDEL}.${VERSIONADD}")
else()
  unset(CMAKESONAME)
endif()

## Library definition

# Add "_imp" as a suffix before the extension to avoid conflicting with
# the statically linked "libcurl.lib" (typically with MSVC)
if(WIN32 AND
   NOT IMPORT_LIB_SUFFIX AND
   CMAKE_STATIC_LIBRARY_SUFFIX STREQUAL CMAKE_IMPORT_LIBRARY_SUFFIX)
  set(IMPORT_LIB_SUFFIX "_imp")
endif()

# Whether to do a single compilation pass for libcurl sources and reuse these
# objects to generate both static and shared target.
if(NOT DEFINED SHARE_LIB_OBJECT)
  # Enable it by default on platforms where PIC is the default for both shared
  # and static and there is a way to tell the linker which libcurl symbols it
  # should export (vs. marking these symbols exportable at compile-time).
  if(WIN32)
    set(SHARE_LIB_OBJECT ON)
  else()
    # On other platforms, make it an option disabled by default
    set(SHARE_LIB_OBJECT OFF)
  endif()
endif()

if(WIN32)
  # Define CURL_STATICLIB always, to disable __declspec(dllexport) for exported
  # libcurl symbols. We handle exports via libcurl.def instead. Except with
  # symbol hiding disabled or debug mode enabled, when we export _all_ symbols
  # from libcurl DLL, without using libcurl.def.
  add_definitions("-DCURL_STATICLIB")
endif()

if(SHARE_LIB_OBJECT)
  set(LIB_OBJECT "libcurl_object")
  add_library(${LIB_OBJECT} OBJECT ${HHEADERS} ${CSOURCES})
  target_link_libraries(${LIB_OBJECT} PRIVATE ${CURL_LIBS})
  set_target_properties(${LIB_OBJECT} PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
  if(HIDES_CURL_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_OBJECT} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_OBJECT} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    set_target_properties(${LIB_OBJECT} PROPERTIES
      INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
      INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
  endif()

  target_include_directories(${LIB_OBJECT} INTERFACE
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CURL_SOURCE_DIR}/include>)

  set(LIB_SOURCE $<TARGET_OBJECTS:${LIB_OBJECT}>)
else()
  set(LIB_SOURCE ${HHEADERS} ${CSOURCES})
endif()

# we want it to be called libcurl on all platforms
if(BUILD_STATIC_LIBS)
  list(APPEND libcurl_export ${LIB_STATIC})
  add_library(${LIB_STATIC} STATIC ${LIB_SOURCE})
  add_library(${PROJECT_NAME}::${LIB_STATIC} ALIAS ${LIB_STATIC})
  target_link_libraries(${LIB_STATIC} PRIVATE ${CURL_LIBS})
  # Remove the "lib" prefix since the library is already named "libcurl".
  set_target_properties(${LIB_STATIC} PROPERTIES
    PREFIX "" OUTPUT_NAME "${LIBCURL_OUTPUT_NAME}"
    SUFFIX "${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}"
    INTERFACE_COMPILE_DEFINITIONS "CURL_STATICLIB")
  if(HIDES_CURL_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_STATIC} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_STATIC} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    set_target_properties(${LIB_STATIC} PROPERTIES
      INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
      INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
  endif()
  if(CMAKEVERSION AND CMAKESONAME)
    set_target_properties(${LIB_STATIC} PROPERTIES
      VERSION ${CMAKEVERSION} SOVERSION ${CMAKESONAME})
  endif()

  target_include_directories(${LIB_STATIC} INTERFACE
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CURL_SOURCE_DIR}/include>)
endif()

if(BUILD_SHARED_LIBS)
  list(APPEND libcurl_export ${LIB_SHARED})
  add_library(${LIB_SHARED} SHARED ${LIB_SOURCE})
  add_library(${PROJECT_NAME}::${LIB_SHARED} ALIAS ${LIB_SHARED})
  if(WIN32)
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES libcurl.rc)
    if(HIDES_CURL_PRIVATE_SYMBOLS)
      set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES "${CURL_SOURCE_DIR}/libcurl.def")
    endif()
  endif()
  target_link_libraries(${LIB_SHARED} PRIVATE ${CURL_LIBS})
  # Remove the "lib" prefix since the library is already named "libcurl".
  set_target_properties(${LIB_SHARED} PROPERTIES
    PREFIX "" OUTPUT_NAME "${LIBCURL_OUTPUT_NAME}"
    IMPORT_PREFIX "" IMPORT_SUFFIX "${IMPORT_LIB_SUFFIX}${CMAKE_IMPORT_LIBRARY_SUFFIX}"
    POSITION_INDEPENDENT_CODE ON)
  if(HIDES_CURL_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    set_target_properties(${LIB_SHARED} PROPERTIES
      INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
      INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
  endif()
  if(CMAKEVERSION AND CMAKESONAME)
    set_target_properties(${LIB_SHARED} PROPERTIES
      VERSION ${CMAKEVERSION} SOVERSION ${CMAKESONAME})
  endif()

  target_include_directories(${LIB_SHARED} INTERFACE
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CURL_SOURCE_DIR}/include>)
endif()

add_library(${LIB_NAME} ALIAS ${LIB_SELECTED})
add_library(${PROJECT_NAME}::${LIB_NAME} ALIAS ${LIB_SELECTED})

if(CURL_ENABLE_EXPORT_TARGET)
  if(BUILD_STATIC_LIBS)
    install(TARGETS ${LIB_STATIC}
      EXPORT ${TARGETS_EXPORT_NAME}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()
  if(BUILD_SHARED_LIBS)
    install(TARGETS ${LIB_SHARED}
      EXPORT ${TARGETS_EXPORT_NAME}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()

  export(TARGETS ${libcurl_export}
         FILE ${PROJECT_BINARY_DIR}/libcurl-target.cmake
         NAMESPACE ${PROJECT_NAME}::
  )
endif()
