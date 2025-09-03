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

set(LIBCURL_OUTPUT_NAME "${LIB_NAME}" CACHE STRING "Basename of the curl library")

set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS ${CURL_DEBUG_MACROS} "BUILDING_LIBCURL")

configure_file("curl_config.h.cmake" "${CMAKE_CURRENT_BINARY_DIR}/curl_config.h")

# Get CSOURCES, HHEADERS, LIB_RCFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

list(APPEND HHEADERS "${CMAKE_CURRENT_BINARY_DIR}/curl_config.h")

# The rest of the build

set_property(DIRECTORY APPEND PROPERTY INCLUDE_DIRECTORIES
  "${PROJECT_BINARY_DIR}/lib"        # for "curl_config.h"
)

if(CURL_BUILD_TESTING)
  # special libcurlu library just for unittests
  add_library(curlu STATIC EXCLUDE_FROM_ALL ${HHEADERS} ${CSOURCES})
  target_compile_definitions(curlu PUBLIC "CURL_STATICLIB" "UNITTESTS")
  target_link_libraries(curlu PRIVATE ${CURL_LIBS})
  # There is plenty of parallelism when building the testdeps target.
  # Override the curlu batch size with the maximum to optimize performance.
  set_target_properties(curlu PROPERTIES UNITY_BUILD_BATCH_SIZE 0 C_CLANG_TIDY "")

  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/unitprotos.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/extract-unit-protos"
      ${CSOURCES} > "${CMAKE_CURRENT_BINARY_DIR}/unitprotos.h"
    DEPENDS "${PROJECT_SOURCE_DIR}/scripts/extract-unit-protos" ${CSOURCES}
    VERBATIM)
  add_custom_target(curlu-unitprotos DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/unitprotos.h")
endif()

## Library definition

if(NOT DEFINED IMPORT_LIB_SUFFIX)
  # Suffix implib name with "_imp" by default, to avoid conflicting with
  # the generated static "libcurl.lib" (typically with MSVC).
  if(WIN32 AND BUILD_SHARED_LIBS AND
     CMAKE_IMPORT_LIBRARY_SUFFIX STREQUAL CMAKE_STATIC_LIBRARY_SUFFIX)
    set(IMPORT_LIB_SUFFIX "_imp")
  else()
    set(IMPORT_LIB_SUFFIX "")
  endif()
endif()
if(NOT DEFINED STATIC_LIB_SUFFIX)
  set(STATIC_LIB_SUFFIX "")
endif()

# Detect implib static lib filename collision
if(WIN32 AND BUILD_STATIC_LIBS AND BUILD_SHARED_LIBS AND
   "${IMPORT_LIB_SUFFIX}${CMAKE_IMPORT_LIBRARY_SUFFIX}" STREQUAL
   "${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  message(FATAL_ERROR "Library suffix is the same ('${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}') "
    "for the import and static '${LIBCURL_OUTPUT_NAME}' library. "
    "Set IMPORT_LIB_SUFFIX and/or STATIC_LIB_SUFFIX to different values, "
    "or disable building either the shared or static library to avoid the filename collision.")
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

if(SHARE_LIB_OBJECT AND CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
  set(LIB_OBJECT "libcurl_object")
  add_library(${LIB_OBJECT} OBJECT ${HHEADERS} ${CSOURCES})  # Requires CMake 3.12
  if(WIN32)
    # Define CURL_STATICLIB always, to disable __declspec(dllexport) for
    # exported libcurl symbols. We handle exports via libcurl.def instead.
    # Except with symbol hiding disabled or debug mode enabled, when we export
    # _all_ symbols from libcurl DLL, without using libcurl.def.
    set_property(TARGET ${LIB_OBJECT} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  target_link_libraries(${LIB_OBJECT} PRIVATE ${CURL_LIBS})
  set_target_properties(${LIB_OBJECT} PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
  if(CURL_HIDES_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_OBJECT} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_OBJECT} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    if(CMAKE_CONFIGURATION_TYPES)
      set_target_properties(${LIB_OBJECT} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
    else()
      set_target_properties(${LIB_OBJECT} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
  endif()

  target_include_directories(${LIB_OBJECT} INTERFACE
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

  set(LIB_SOURCE $<TARGET_OBJECTS:${LIB_OBJECT}>)
else()
  set(LIB_SOURCE ${HHEADERS} ${CSOURCES})
endif()

# We want it to be called libcurl on all platforms
if(BUILD_STATIC_LIBS)
  list(APPEND libcurl_export ${LIB_STATIC})
  add_library(${LIB_STATIC} STATIC ${LIB_SOURCE})
  add_library(${PROJECT_NAME}::${LIB_STATIC} ALIAS ${LIB_STATIC})
  if(WIN32)
    set_property(TARGET ${LIB_STATIC} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  target_link_libraries(${LIB_STATIC} PRIVATE ${CURL_LIBS})
  # Remove the "lib" prefix since the library is already named "libcurl".
  set_target_properties(${LIB_STATIC} PROPERTIES
    PREFIX "" OUTPUT_NAME "${LIBCURL_OUTPUT_NAME}"
    SUFFIX "${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}"
    INTERFACE_COMPILE_DEFINITIONS "CURL_STATICLIB"
    INTERFACE_LINK_DIRECTORIES "${CURL_LIBDIRS}")
  if(CURL_HIDES_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_STATIC} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_STATIC} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    if(CMAKE_CONFIGURATION_TYPES)
      set_target_properties(${LIB_STATIC} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
    else()
      set_target_properties(${LIB_STATIC} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
  endif()

  target_include_directories(${LIB_STATIC} INTERFACE
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")
endif()

if(BUILD_SHARED_LIBS)
  list(APPEND libcurl_export ${LIB_SHARED})
  add_library(${LIB_SHARED} SHARED ${LIB_SOURCE})
  add_library(${PROJECT_NAME}::${LIB_SHARED} ALIAS ${LIB_SHARED})
  if(WIN32)
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES "dllmain.c")
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES ${LIB_RCFILES})
    if(CURL_HIDES_PRIVATE_SYMBOLS)
      set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES "${PROJECT_SOURCE_DIR}/lib/libcurl.def")
    endif()
  endif()
  target_link_libraries(${LIB_SHARED} PRIVATE ${CURL_LIBS})
  # Remove the "lib" prefix since the library is already named "libcurl".
  set_target_properties(${LIB_SHARED} PROPERTIES
    PREFIX "" OUTPUT_NAME "${LIBCURL_OUTPUT_NAME}"
    IMPORT_PREFIX "" IMPORT_SUFFIX "${IMPORT_LIB_SUFFIX}${CMAKE_IMPORT_LIBRARY_SUFFIX}"
    POSITION_INDEPENDENT_CODE ON)
  if(CURL_HIDES_PRIVATE_SYMBOLS)
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY COMPILE_FLAGS "${CURL_CFLAG_SYMBOLS_HIDE}")
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
  endif()
  if(CURL_HAS_LTO)
    if(CMAKE_CONFIGURATION_TYPES)
      set_target_properties(${LIB_SHARED} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
    else()
      set_target_properties(${LIB_SHARED} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
  endif()

  target_include_directories(${LIB_SHARED} INTERFACE
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>")

  if(CMAKE_DLL_NAME_WITH_SOVERSION OR
    CYGWIN OR
    APPLE OR
    CMAKE_SYSTEM_NAME STREQUAL "AIX" OR
    CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
    CMAKE_SYSTEM_NAME STREQUAL "SunOS" OR
    CMAKE_SYSTEM_NAME STREQUAL "Haiku" OR
    CMAKE_SYSTEM_NAME STREQUAL "OHOS" OR  # OpenHarmony
    CMAKE_SYSTEM_NAME STREQUAL "GNU/kFreeBSD" OR
    # FreeBSD comes with the a.out and ELF flavours but a.out was supported
    # up to v3.x and ELF from v3.x. I cannot imagine someone running CMake
    # on those ancient systems.
    CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(_soversion_default TRUE)
  else()
    set(_soversion_default FALSE)
  endif()

  option(CURL_LIBCURL_SOVERSION "Enable libcurl SOVERSION" ${_soversion_default})
  option(CURL_LIBCURL_VERSIONED_SYMBOLS "Enable libcurl versioned symbols" OFF)

  if(CURL_LIBCURL_SOVERSION OR CURL_LIBCURL_VERSIONED_SYMBOLS)
    # Get VERSIONCHANGE, VERSIONADD, VERSIONDEL, VERSIONINFO variables
    curl_transform_makefile_inc("Makefile.soname" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake")
    include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.soname.cmake")

    math(EXPR _cmakesoname "${VERSIONCHANGE} - ${VERSIONDEL}")
    set(_cmakeversion "${_cmakesoname}.${VERSIONDEL}.${VERSIONADD}")
  endif()

  if(CURL_LIBCURL_SOVERSION)
    set_target_properties(${LIB_SHARED} PROPERTIES
      VERSION "${_cmakeversion}" SOVERSION "${_cmakesoname}")
  endif()

  ## Versioned symbols

  if(CURL_LIBCURL_VERSIONED_SYMBOLS)
    if(NOT DEFINED CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX)
      # Default to prefixes used by autotools
      if(CURL_WITH_MULTI_SSL)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "MULTISSL_")
      elseif(CURL_USE_OPENSSL)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "OPENSSL_")
      elseif(CURL_USE_MBEDTLS)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "MBEDTLS_")
      elseif(CURL_USE_WOLFSSL)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "WOLFSSL_")
      elseif(CURL_USE_GNUTLS)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "GNUTLS_")
      elseif(CURL_USE_RUSTLS)
        set(CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX "RUSTLS_")
      endif()
    endif()
    # Generate version script for the linker, for versioned symbols.
    # Consumed variables:
    #   CURL_LIBCURL_VERSIONED_SYMBOLS_PREFIX
    #   CURL_LIBCURL_VERSIONED_SYMBOLS_SONAME
    set(CURL_LIBCURL_VERSIONED_SYMBOLS_SONAME ${_cmakesoname})
    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/libcurl.vers.in"
      "${CMAKE_CURRENT_BINARY_DIR}/libcurl.vers" @ONLY)
    include(CMakePushCheckState)
    include(CheckCSourceCompiles)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/libcurl.vers")
    check_c_source_compiles("int main(void) { return 0; }" HAVE_VERSIONED_SYMBOLS)
    if(HAVE_VERSIONED_SYMBOLS)
      if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        set_target_properties(${LIB_SHARED} PROPERTIES LINK_OPTIONS "${CMAKE_REQUIRED_LINK_OPTIONS}")
      else()
        set_target_properties(${LIB_SHARED} PROPERTIES LINK_FLAGS "${CMAKE_REQUIRED_LINK_OPTIONS}")
      endif()
    else()
      message(WARNING "Versioned symbols requested, but not supported by the toolchain.")
    endif()
    cmake_pop_check_state()
  endif()
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
    FILE "${PROJECT_BINARY_DIR}/libcurl-target.cmake"
    NAMESPACE ${PROJECT_NAME}::
  )
endif()
