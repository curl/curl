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
#***************************************************************************
cmake_minimum_required(VERSION 3.18)

project(schannel-mockup
  VERSION 0.1.0
  DESCRIPTION "Windows Schannel (SSPI) & CryptoAPI mockup library using OpenSSL"
  LANGUAGES C
)

include(GNUInstallDirs)

option(ENABLE_WERROR "Treat warnings as errors" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  add_compile_options(-Wall -Wextra -pedantic)
  if(ENABLE_WERROR)
    add_compile_options(-Werror)
  endif()
endif()

# Check for OpenSSL
find_package(OpenSSL 1.1.1 REQUIRED)

set(CSOURCES
  src/mock_sspi.c
  src/mock_win32.c
  src/mock_compat.c
  src/mock_crypto.c
  src/mock_x509.c
  src/mock_hash.c
)

set(HHEADERS
  include/curl_win32.h
  include/ntsecapi.h
  include/schannel.h
  include/security.h
  include/sspi.h
  include/subauth.h
  include/wincrypt.h
  include/windows.h
)

add_library(schannelmockup ${CSOURCES} ${HHEADERS})
add_library(schannelmockup::schannelmockup ALIAS schannelmockup)

set_target_properties(schannelmockup PROPERTIES
  OUTPUT_NAME "schannelmockup"
  POSITION_INDEPENDENT_CODE ON
)

target_include_directories(schannelmockup
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(schannelmockup
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# pkg-config file generation
set(prefix "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "\${prefix}")
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
  set(libdir "${CMAKE_INSTALL_LIBDIR}")
else()
  set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
  set(includedir "${CMAKE_INSTALL_INCLUDEDIR}")
else()
  set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()
set(PACKAGE_VERSION "${PROJECT_VERSION}")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/schannel-mockup.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/schannel-mockup.pc"
  @ONLY
)

# Installation rules
install(TARGETS schannelmockup
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES ${HHEADERS}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/schannel-mockup.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

# checksrc target
find_program(PERL_EXECUTABLE NAMES perl)
set(_checksrc "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/checksrc.pl")
if(PERL_EXECUTABLE AND EXISTS "${_checksrc}")
  add_custom_target(checksrc
    COMMAND ${PERL_EXECUTABLE} "${_checksrc}" -D. ${CSOURCES} ${HHEADERS}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "RUN      checksrc"
    VERBATIM
  )
endif()

# Tests
include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
  if(TARGET checksrc AND TARGET checksrc-tests)
    add_dependencies(checksrc checksrc-tests)
  endif()
  add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    USES_TERMINAL
  )
endif()
