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
# by Tetetest and Sukender (Benoit Neil)

# Note: By default this CMake build script detects the version of some
# dependencies using `check_symbol_exists`. Those checks do not work in
# the case that both CURL and its dependency are included as sub-projects
# in a larger build using `FetchContent`. To support that case, additional
# variables may be defined by the parent project, ideally in the "extra"
# find package redirect file:
# https://cmake.org/cmake/help/latest/module/FetchContent.html#integrating-with-find-package
#
# The following variables are available:
#   HAVE_SSL_SET0_WBIO: `SSL_set0_wbio` present in OpenSSL/wolfSSL
#   HAVE_OPENSSL_SRP: `SSL_CTX_set_srp_username` present in OpenSSL/wolfSSL
#   HAVE_GNUTLS_SRP: `gnutls_srp_verifier` present in GnuTLS
#   HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT: `SSL_set_quic_use_legacy_codepoint` present in OpenSSL/wolfSSL
#   HAVE_QUICHE_CONN_SET_QLOG_FD: `quiche_conn_set_qlog_fd` present in quiche
#   HAVE_ECH: ECH API checks for OpenSSL, BoringSSL or wolfSSL
#
# For each of the above variables, if the variable is DEFINED (either
# to ON or OFF), the symbol detection is skipped.  If the variable is
# NOT DEFINED, the symbol detection is performed.

cmake_minimum_required(VERSION 3.7...3.16 FATAL_ERROR)
message(STATUS "Using CMake version ${CMAKE_VERSION}")

# Collect command-line arguments for buildinfo.txt.
# Must reside at the top of the script to work as expected.
set(_cmake_args "")
if(NOT "$ENV{CURL_BUILDINFO}$ENV{CURL_CI}$ENV{CI}" STREQUAL "")
  get_cmake_property(_cache_vars CACHE_VARIABLES)
  foreach(_cache_var IN ITEMS ${_cache_vars})
    get_property(_cache_var_helpstring CACHE ${_cache_var} PROPERTY HELPSTRING)
    if(_cache_var_helpstring STREQUAL "No help, variable specified on the command line.")
      get_property(_cache_var_type CACHE ${_cache_var} PROPERTY TYPE)
      get_property(_cache_var_value CACHE ${_cache_var} PROPERTY VALUE)
      if(_cache_var_type STREQUAL "UNINITIALIZED")
        set(_cache_var_type)
      else()
        set(_cache_var_type ":${_cache_var_type}")
      endif()
      set(_cmake_args "${_cmake_args} -D${_cache_var}${_cache_var_type}=\"${_cache_var_value}\"")
    endif()
  endforeach()
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")
include(Utilities)
include(Macros)
include(CMakeDependentOption)
include(CheckCCompilerFlag)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/curl/curlver.h" _curl_version_h_contents REGEX "#define LIBCURL_VERSION( |_NUM )")
string(REGEX MATCH "#define LIBCURL_VERSION \"[^\"]*" _curl_version ${_curl_version_h_contents})
string(REGEX REPLACE "[^\"]+\"" "" _curl_version ${_curl_version})
string(REGEX MATCH "#define LIBCURL_VERSION_NUM 0x[0-9a-fA-F]+" _curl_version_num ${_curl_version_h_contents})
string(REGEX REPLACE "[^0]+0x" "" _curl_version_num ${_curl_version_num})
unset(_curl_version_h_contents)

message(STATUS "curl version=[${_curl_version}]")

string(REGEX REPLACE "([0-9]+\.[0-9]+\.[0-9]+).+" "\\1" _curl_version_sem "${_curl_version}")
project(CURL
  VERSION "${_curl_version_sem}"
  LANGUAGES C)

# CMake does not recognize some targets accurately. Touch up configuration manually as a workaround.
if(WINDOWS_STORE AND MINGW)  # mingw UWP build
  # CMake (as of v3.31.2) gets confused and applies the MSVC rc.exe command-line
  # template to windres. Reset it to the windres template via 'Modules/Platform/Windows-windres.cmake':
  set(CMAKE_RC_COMPILE_OBJECT "<CMAKE_RC_COMPILER> -O coff <DEFINES> <INCLUDES> <FLAGS> <SOURCE> <OBJECT>")
elseif(DOS AND CMAKE_COMPILER_IS_GNUCC)  # DJGPP
  set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
  set(CMAKE_STATIC_LIBRARY_SUFFIX ".a")
  set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

# Fill platform level variable when using CMake's built-in Android configuration
if(ANDROID AND NOT DEFINED ANDROID_PLATFORM_LEVEL AND NOT CMAKE_SYSTEM_VERSION EQUAL 1)
  set(ANDROID_PLATFORM_LEVEL "${CMAKE_SYSTEM_VERSION}")
endif()

set(_target_flags "")
if(APPLE)
  set(_target_flags "${_target_flags} APPLE")
endif()
if(UNIX)
  set(_target_flags "${_target_flags} UNIX")
endif()
if(BSD)
  set(_target_flags "${_target_flags} BSD")
endif()
if(ANDROID)
  set(_target_flags "${_target_flags} ANDROID-${ANDROID_PLATFORM_LEVEL}")
endif()
if(WIN32)
  set(_target_flags "${_target_flags} WIN32")
endif()
if(WINDOWS_STORE)
  set(_target_flags "${_target_flags} UWP")
endif()
if(CYGWIN)
  set(_target_flags "${_target_flags} CYGWIN")
endif()
if(MSYS)
  set(_target_flags "${_target_flags} MSYS")
endif()
if(DOS)
  set(_target_flags "${_target_flags} DOS")
endif()
if(AMIGA)
  set(_target_flags "${_target_flags} AMIGA")
endif()
if(CMAKE_COMPILER_IS_GNUCC)
  set(_target_flags "${_target_flags} GCC")
endif()
if(MINGW)
  set(_target_flags "${_target_flags} MINGW")
endif()
if(MSVC)
  set(_target_flags "${_target_flags} MSVC-${MSVC_VERSION}")
endif()
if(VCPKG_TOOLCHAIN)
  set(_target_flags "${_target_flags} VCPKG")
endif()
if(CMAKE_CROSSCOMPILING)
  set(_target_flags "${_target_flags} CROSS")
endif()
message(STATUS "CMake platform flags:${_target_flags}")

if(CMAKE_CROSSCOMPILING)
  message(STATUS "Cross-compiling: "
    "${CMAKE_HOST_SYSTEM_NAME}/${CMAKE_HOST_SYSTEM_PROCESSOR} -> "
    "${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(CMAKE_C_COMPILER_TARGET)
  set(CURL_OS "\"${CMAKE_C_COMPILER_TARGET}\"")
else()
  set(CURL_OS "\"${CMAKE_SYSTEM_NAME}\"")
endif()

include_directories("${PROJECT_SOURCE_DIR}/include")

if(NOT DEFINED CMAKE_UNITY_BUILD_BATCH_SIZE)
  set(CMAKE_UNITY_BUILD_BATCH_SIZE 0)
endif()

# Having CMAKE_TRY_COMPILE_TARGET_TYPE set to STATIC_LIBRARY breaks certain
# 'check_function_exists()' detections (possibly more), by detecting
# non-existing features. This happens by default when using 'ios.toolchain.cmake'.
# Work it around by setting this value to `EXECUTABLE`.
if(CMAKE_TRY_COMPILE_TARGET_TYPE STREQUAL "STATIC_LIBRARY")
  message(STATUS "CMAKE_TRY_COMPILE_TARGET_TYPE was found set to STATIC_LIBRARY. "
    "Overriding with EXECUTABLE for feature detections to work.")
  set(_cmake_try_compile_target_type_save ${CMAKE_TRY_COMPILE_TARGET_TYPE})
  set(CMAKE_TRY_COMPILE_TARGET_TYPE "EXECUTABLE")
endif()

option(CURL_WERROR "Turn compiler warnings into errors" OFF)
option(PICKY_COMPILER "Enable picky compiler options" ON)
option(BUILD_CURL_EXE "Build curl executable" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" OFF)
option(BUILD_STATIC_CURL "Build curl executable with static libcurl" OFF)
option(ENABLE_ARES "Enable c-ares support" OFF)
option(CURL_DISABLE_INSTALL "Disable installation targets" OFF)

if(WIN32)
  option(CURL_STATIC_CRT "Build libcurl with static CRT with MSVC (/MT)" OFF)
  if(CURL_STATIC_CRT AND MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
  endif()

  option(ENABLE_UNICODE "Use the Unicode version of the Windows API functions" OFF)
  if(WINDOWS_STORE)
    set(ENABLE_UNICODE ON)
  endif()
  if(ENABLE_UNICODE)
    add_definitions("-DUNICODE" "-D_UNICODE")
    if(MINGW)
      add_compile_options("-municode")
    endif()
  endif()

  list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DWIN32_LEAN_AND_MEAN")  # Apply to all feature checks

  set(CURL_TARGET_WINDOWS_VERSION "" CACHE STRING "Minimum target Windows version as hex string")
  if(CURL_TARGET_WINDOWS_VERSION)
    add_definitions("-D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION}")  # Apply to all feature checks
  endif()

  # Detect actual value of _WIN32_WINNT and store as HAVE_WIN32_WINNT
  curl_internal_test(HAVE_WIN32_WINNT)
  if(HAVE_WIN32_WINNT)
    string(REGEX MATCH "_WIN32_WINNT=0x[0-9a-fA-F]+" CURL_TEST_OUTPUT "${CURL_TEST_OUTPUT}")
    string(REGEX REPLACE "_WIN32_WINNT=" "" CURL_TEST_OUTPUT "${CURL_TEST_OUTPUT}")
    string(REGEX REPLACE "0x([0-9a-f][0-9a-f][0-9a-f])$" "0x0\\1" CURL_TEST_OUTPUT "${CURL_TEST_OUTPUT}")  # pad to 4 digits
    string(TOLOWER "${CURL_TEST_OUTPUT}" HAVE_WIN32_WINNT)
    message(STATUS "Found _WIN32_WINNT=${HAVE_WIN32_WINNT}")
  endif()
  unset(HAVE_WIN32_WINNT CACHE)  # Avoid storing in CMake cache

  if(MINGW)
    # Detect __MINGW64_VERSION_MAJOR, __MINGW64_VERSION_MINOR and store as MINGW64_VERSION
    curl_internal_test(MINGW64_VERSION)
    if(MINGW64_VERSION)
      string(REGEX MATCH "MINGW64_VERSION=[0-9]+\.[0-9]+" CURL_TEST_OUTPUT "${CURL_TEST_OUTPUT}")
      string(REGEX REPLACE "MINGW64_VERSION=" "" MINGW64_VERSION "${CURL_TEST_OUTPUT}")
      message(STATUS "Found MINGW64_VERSION=${MINGW64_VERSION}")
    endif()
    unset(MINGW64_VERSION CACHE)  # Avoid storing in CMake cache
  endif()
elseif(DOS OR AMIGA)
  set(BUILD_SHARED_LIBS OFF)
  set(BUILD_STATIC_LIBS ON)
endif()
option(CURL_LTO "Enable compiler Link Time Optimizations" OFF)

if(NOT DOS AND NOT AMIGA)
  # if c-ares is used, default the threaded resolver to OFF
  if(ENABLE_ARES)
    set(_enable_threaded_resolver_default OFF)
  else()
    set(_enable_threaded_resolver_default ON)
  endif()
  option(ENABLE_THREADED_RESOLVER "Enable threaded DNS lookup" ${_enable_threaded_resolver_default})
endif()

include(PickyWarnings)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")  # Required for sendmmsg()
endif()

option(ENABLE_DEBUG "Enable curl debug features (for developing curl itself)" OFF)
if(ENABLE_DEBUG)
  message(WARNING "This curl build is Debug-enabled, do not use in production.")
endif()
option(ENABLE_CURLDEBUG "Enable TrackMemory debug feature" ${ENABLE_DEBUG})

if(MSVC)
  set(ENABLE_CURLDEBUG OFF)  # FIXME: TrackMemory + MSVC fails test 558 and 1330. Tested with static build, Debug mode.
endif()

if(ENABLE_DEBUG)
  set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS "DEBUGBUILD")
endif()

if(ENABLE_CURLDEBUG)
  set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS "CURLDEBUG")
endif()

option(CURL_CLANG_TIDY "Run the build through clang-tidy" OFF)
if(CURL_CLANG_TIDY)
  set(CMAKE_UNITY_BUILD OFF)
  set(_tidy_checks "")
  list(APPEND _tidy_checks "-clang-analyzer-security.insecureAPI.strcpy")
  list(APPEND _tidy_checks "-clang-analyzer-optin.performance.Padding")
  list(APPEND _tidy_checks "-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling")
  string(REPLACE ";" "," _tidy_checks "${_tidy_checks}")
  find_program(CLANG_TIDY NAMES "clang-tidy" REQUIRED)
  set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY}" "-checks=${_tidy_checks}" "-quiet")
  unset(_tidy_checks)
  if(CURL_WERROR)
    list(APPEND CMAKE_C_CLANG_TIDY "--warnings-as-errors=*")
  endif()
  if(CURL_CLANG_TIDYFLAGS)
    list(APPEND CMAKE_C_CLANG_TIDY ${CURL_CLANG_TIDYFLAGS})
  endif()
endif()

# For debug libs and exes, add "-d" postfix
if(NOT DEFINED CMAKE_DEBUG_POSTFIX)
  set(CMAKE_DEBUG_POSTFIX "-d")
endif()

set(LIB_STATIC "libcurl_static")
set(LIB_SHARED "libcurl_shared")

if(NOT BUILD_SHARED_LIBS AND NOT BUILD_STATIC_LIBS)
  set(BUILD_STATIC_LIBS ON)
endif()
if(NOT BUILD_STATIC_CURL AND NOT BUILD_SHARED_LIBS)
  set(BUILD_STATIC_CURL ON)
elseif(BUILD_STATIC_CURL AND NOT BUILD_STATIC_LIBS)
  set(BUILD_STATIC_CURL OFF)
endif()

# Lib flavour selected for curl tool
if(BUILD_STATIC_CURL)
  set(LIB_SELECTED_FOR_EXE ${LIB_STATIC})
else()
  set(LIB_SELECTED_FOR_EXE ${LIB_SHARED})
endif()

# Lib flavour selected for example and test programs.
if(BUILD_SHARED_LIBS)
  set(LIB_SELECTED ${LIB_SHARED})
else()
  set(LIB_SELECTED ${LIB_STATIC})
endif()

# Override to force-disable or force-enable the use of pkg-config.
if((UNIX AND NOT ANDROID AND (NOT APPLE OR CMAKE_SYSTEM_NAME MATCHES "Darwin")) OR
   VCPKG_TOOLCHAIN OR
   (MINGW AND NOT CMAKE_CROSSCOMPILING))
  set(_curl_use_pkgconfig_default ON)
else()
  set(_curl_use_pkgconfig_default OFF)
endif()
option(CURL_USE_PKGCONFIG "Enable pkg-config to detect dependencies" ${_curl_use_pkgconfig_default})

# Initialize variables collecting dependency libs, paths, pkg-config names.
set(CURL_LIBS "")
set(CURL_LIBDIRS "")
set(LIBCURL_PC_REQUIRES_PRIVATE "")

if(ENABLE_ARES)
  set(USE_ARES 1)
  find_package(Cares REQUIRED)
  list(APPEND CURL_LIBS ${CARES_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${CARES_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${CARES_PC_REQUIRES})
  link_directories(${CARES_LIBRARY_DIRS})
  if(CARES_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CARES_CFLAGS}")
  endif()
endif()

include(CurlSymbolHiding)

option(CURL_ENABLE_EXPORT_TARGET "Enable CMake export target" ON)
mark_as_advanced(CURL_ENABLE_EXPORT_TARGET)

option(CURL_DISABLE_ALTSVC "Disable alt-svc support" OFF)
mark_as_advanced(CURL_DISABLE_ALTSVC)
option(CURL_DISABLE_SRP "Disable TLS-SRP support" OFF)
mark_as_advanced(CURL_DISABLE_SRP)
option(CURL_DISABLE_COOKIES "Disable cookies support" OFF)
mark_as_advanced(CURL_DISABLE_COOKIES)
option(CURL_DISABLE_BASIC_AUTH "Disable Basic authentication" OFF)
mark_as_advanced(CURL_DISABLE_BASIC_AUTH)
option(CURL_DISABLE_BEARER_AUTH "Disable Bearer authentication" OFF)
mark_as_advanced(CURL_DISABLE_BEARER_AUTH)
option(CURL_DISABLE_DIGEST_AUTH "Disable Digest authentication" OFF)
mark_as_advanced(CURL_DISABLE_DIGEST_AUTH)
option(CURL_DISABLE_KERBEROS_AUTH "Disable Kerberos authentication" OFF)
mark_as_advanced(CURL_DISABLE_KERBEROS_AUTH)
option(CURL_DISABLE_NEGOTIATE_AUTH "Disable negotiate authentication" OFF)
mark_as_advanced(CURL_DISABLE_NEGOTIATE_AUTH)
option(CURL_DISABLE_AWS "Disable aws-sigv4" OFF)
mark_as_advanced(CURL_DISABLE_AWS)
option(CURL_DISABLE_DICT "Disable DICT" OFF)
mark_as_advanced(CURL_DISABLE_DICT)
option(CURL_DISABLE_DOH "Disable DNS-over-HTTPS" OFF)
mark_as_advanced(CURL_DISABLE_DOH)
option(CURL_DISABLE_FILE "Disable FILE" OFF)
mark_as_advanced(CURL_DISABLE_FILE)
option(CURL_DISABLE_FTP "Disable FTP" OFF)
mark_as_advanced(CURL_DISABLE_FTP)
option(CURL_DISABLE_GETOPTIONS "Disable curl_easy_options API for existing options to curl_easy_setopt" OFF)
mark_as_advanced(CURL_DISABLE_GETOPTIONS)
option(CURL_DISABLE_GOPHER "Disable Gopher" OFF)
mark_as_advanced(CURL_DISABLE_GOPHER)
option(CURL_DISABLE_HEADERS_API "Disable headers-api support" OFF)
mark_as_advanced(CURL_DISABLE_HEADERS_API)
option(CURL_DISABLE_HSTS "Disable HSTS support" OFF)
mark_as_advanced(CURL_DISABLE_HSTS)
option(CURL_DISABLE_HTTP "Disable HTTP" OFF)
mark_as_advanced(CURL_DISABLE_HTTP)
option(CURL_DISABLE_HTTP_AUTH "Disable all HTTP authentication methods" OFF)
mark_as_advanced(CURL_DISABLE_HTTP_AUTH)
option(CURL_DISABLE_IMAP "Disable IMAP" OFF)
mark_as_advanced(CURL_DISABLE_IMAP)
option(CURL_DISABLE_LDAP "Disable LDAP" OFF)
mark_as_advanced(CURL_DISABLE_LDAP)
option(CURL_DISABLE_LDAPS "Disable LDAPS" ${CURL_DISABLE_LDAP})
mark_as_advanced(CURL_DISABLE_LDAPS)
option(CURL_DISABLE_LIBCURL_OPTION "Disable --libcurl option from the curl tool" OFF)
mark_as_advanced(CURL_DISABLE_LIBCURL_OPTION)
option(CURL_DISABLE_MIME "Disable MIME support" OFF)
mark_as_advanced(CURL_DISABLE_MIME)
cmake_dependent_option(CURL_DISABLE_FORM_API "Disable form-api"
  OFF "NOT CURL_DISABLE_MIME"
  ON)
mark_as_advanced(CURL_DISABLE_FORM_API)
option(CURL_DISABLE_MQTT "Disable MQTT" OFF)
mark_as_advanced(CURL_DISABLE_MQTT)
option(CURL_DISABLE_BINDLOCAL "Disable local binding support" OFF)
mark_as_advanced(CURL_DISABLE_BINDLOCAL)
option(CURL_DISABLE_NETRC "Disable netrc parser" OFF)
mark_as_advanced(CURL_DISABLE_NETRC)
option(CURL_DISABLE_NTLM "Disable NTLM support" OFF)
mark_as_advanced(CURL_DISABLE_NTLM)
option(CURL_DISABLE_PARSEDATE "Disable date parsing" OFF)
mark_as_advanced(CURL_DISABLE_PARSEDATE)
option(CURL_DISABLE_POP3 "Disable POP3" OFF)
mark_as_advanced(CURL_DISABLE_POP3)
option(CURL_DISABLE_PROGRESS_METER "Disable built-in progress meter" OFF)
mark_as_advanced(CURL_DISABLE_PROGRESS_METER)
option(CURL_DISABLE_PROXY "Disable proxy support" OFF)
mark_as_advanced(CURL_DISABLE_PROXY)
option(CURL_DISABLE_IPFS "Disable IPFS" OFF)
mark_as_advanced(CURL_DISABLE_IPFS)
option(CURL_DISABLE_RTSP "Disable RTSP" OFF)
mark_as_advanced(CURL_DISABLE_SHA512_256)
option(CURL_DISABLE_SHA512_256 "Disable SHA-512/256 hash algorithm" OFF)
mark_as_advanced(CURL_DISABLE_RTSP)
option(CURL_DISABLE_SHUFFLE_DNS "Disable shuffle DNS feature" OFF)
mark_as_advanced(CURL_DISABLE_SHUFFLE_DNS)
option(CURL_DISABLE_SMB "Disable SMB" OFF)
mark_as_advanced(CURL_DISABLE_SMB)
option(CURL_DISABLE_SMTP "Disable SMTP" OFF)
mark_as_advanced(CURL_DISABLE_SMTP)
option(CURL_DISABLE_SOCKETPAIR "Disable use of socketpair for curl_multi_poll" OFF)
mark_as_advanced(CURL_DISABLE_SOCKETPAIR)
option(CURL_DISABLE_WEBSOCKETS "Disable WebSocket" OFF)
mark_as_advanced(CURL_DISABLE_WEBSOCKETS)
option(CURL_DISABLE_TELNET "Disable Telnet" OFF)
mark_as_advanced(CURL_DISABLE_TELNET)
option(CURL_DISABLE_TFTP "Disable TFTP" OFF)
mark_as_advanced(CURL_DISABLE_TFTP)
option(CURL_DISABLE_VERBOSE_STRINGS "Disable verbose strings" OFF)
mark_as_advanced(CURL_DISABLE_VERBOSE_STRINGS)

if(CURL_DISABLE_HTTP)
  set(CURL_DISABLE_IPFS ON)
  set(CURL_DISABLE_RTSP ON)
  set(CURL_DISABLE_ALTSVC ON)
  set(CURL_DISABLE_HSTS ON)
endif()

# Corresponds to HTTP_ONLY in lib/curl_setup.h
option(HTTP_ONLY "Disable all protocols except HTTP (This overrides all CURL_DISABLE_* options)" OFF)
mark_as_advanced(HTTP_ONLY)

if(HTTP_ONLY)
  set(CURL_DISABLE_DICT ON)
  set(CURL_DISABLE_FILE ON)
  set(CURL_DISABLE_FTP ON)
  set(CURL_DISABLE_GOPHER ON)
  set(CURL_DISABLE_IMAP ON)
  set(CURL_DISABLE_LDAP ON)
  set(CURL_DISABLE_LDAPS ON)
  set(CURL_DISABLE_MQTT ON)
  set(CURL_DISABLE_POP3 ON)
  set(CURL_DISABLE_IPFS ON)
  set(CURL_DISABLE_RTSP ON)
  set(CURL_DISABLE_SMB ON)
  set(CURL_DISABLE_SMTP ON)
  set(CURL_DISABLE_TELNET ON)
  set(CURL_DISABLE_TFTP ON)
endif()

if(WINDOWS_STORE)
  set(CURL_DISABLE_TELNET ON)  # telnet code needs fixing to compile for UWP.
endif()

option(ENABLE_IPV6 "Enable IPv6 support" ON)
mark_as_advanced(ENABLE_IPV6)
if(ENABLE_IPV6 AND NOT WIN32)
  include(CheckStructHasMember)
  check_struct_has_member("struct sockaddr_in6" "sin6_addr" "netinet/in.h" HAVE_SOCKADDR_IN6_SIN6_ADDR)
  check_struct_has_member("struct sockaddr_in6" "sin6_scope_id" "netinet/in.h" HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(NOT HAVE_SOCKADDR_IN6_SIN6_ADDR)
    if(NOT DOS AND NOT AMIGA)
      message(WARNING "struct sockaddr_in6 not available, disabling IPv6 support")
    endif()
    # Force the feature off as this name is used as guard macro...
    set(ENABLE_IPV6 OFF CACHE BOOL "Enable IPv6 support" FORCE)
  endif()

  if(APPLE AND NOT ENABLE_ARES)
    set(_use_core_foundation_and_core_services ON)

    find_library(SYSTEMCONFIGURATION_FRAMEWORK NAMES "SystemConfiguration")
    mark_as_advanced(SYSTEMCONFIGURATION_FRAMEWORK)
    if(NOT SYSTEMCONFIGURATION_FRAMEWORK)
      message(FATAL_ERROR "SystemConfiguration framework not found")
    endif()
    list(APPEND CURL_LIBS "-framework SystemConfiguration")
  endif()
endif()
if(ENABLE_IPV6)
  set(USE_IPV6 ON)
endif()

find_package(Perl)

if(PERL_EXECUTABLE)
  add_custom_target(curl-ca-bundle
    COMMENT "Generating a fresh ca-bundle.crt" VERBATIM USES_TERMINAL
    COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/mk-ca-bundle.pl" -b -l -u "lib/ca-bundle.crt"
    DEPENDS "${PROJECT_SOURCE_DIR}/scripts/mk-ca-bundle.pl"
  )
  add_custom_target(curl-ca-firefox
    COMMENT "generating a fresh ca-bundle.crt" VERBATIM USES_TERMINAL
    COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/firefox-db2pem.sh" "lib/ca-bundle.crt"
    DEPENDS "${PROJECT_SOURCE_DIR}/scripts/firefox-db2pem.sh"
  )
endif()

option(BUILD_LIBCURL_DOCS "Build libcurl man pages" ON)
option(BUILD_MISC_DOCS "Build misc man pages (e.g. curl-config and mk-ca-bundle)" ON)
option(ENABLE_CURL_MANUAL "Build the man page for curl and enable its -M/--manual option" ON)

if(ENABLE_CURL_MANUAL OR BUILD_LIBCURL_DOCS)
  if(PERL_FOUND)
    set(HAVE_MANUAL_TOOLS ON)
  endif()
  if(NOT HAVE_MANUAL_TOOLS)
    message(WARNING "Perl not found. Will not build manuals.")
  endif()
endif()

# Disable warnings on Borland to avoid changing 3rd party code.
if(BORLAND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w-")
endif()

# If we are on AIX, do the _ALL_SOURCE magic
if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
  add_definitions("-D_ALL_SOURCE")
endif()

# If we are on Haiku, make sure that the network library is brought in.
if(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
  list(APPEND CURL_LIBS "network")
elseif(AMIGA)
  list(APPEND CURL_LIBS "net" "m" "atomic")
  list(APPEND CMAKE_REQUIRED_LIBRARIES "net" "m" "atomic")
endif()

# Include all the necessary files for macros
include(CMakePushCheckState)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)
include(CheckCSourceCompiles)

if(WIN32)
  # Preload settings on Windows
  include("${CMAKE_CURRENT_SOURCE_DIR}/CMake/win32-cache.cmake")
elseif(APPLE)
  # Fast-track predictable feature detections
  set(HAVE_EVENTFD 0)
  set(HAVE_GETPASS_R 0)
  set(HAVE_SENDMMSG 0)
elseif(AMIGA)
  set(HAVE_GETADDRINFO 0)  # Breaks the build when detected and used.
endif()
if(DOS OR AMIGA)
  set(HAVE_TIME_T_UNSIGNED 1)
endif()

if(ENABLE_THREADED_RESOLVER)
  if(WIN32)
    set(USE_THREADS_WIN32 ON)
  else()
    find_package(Threads REQUIRED)
    set(USE_THREADS_POSIX ${CMAKE_USE_PTHREADS_INIT})
    set(HAVE_PTHREAD_H ${CMAKE_USE_PTHREADS_INIT})
    list(APPEND CURL_LIBS ${CMAKE_THREAD_LIBS_INIT})
  endif()
endif()

# Check for all needed libraries
if(DOS)
  if(WATT_ROOT)
    set(USE_WATT32 ON)
    # FIXME upstream: must specify the full path to avoid CMake converting "watt" to "watt.lib"
    list(APPEND CURL_LIBS "${WATT_ROOT}/lib/libwatt.a")
    include_directories(SYSTEM "${WATT_ROOT}/inc")
    list(APPEND CMAKE_REQUIRED_INCLUDES "${WATT_ROOT}/inc")
  else()
    message(FATAL_ERROR "Set WATT_ROOT variable to the root installation of Watt-32.")
  endif()
elseif(AMIGA)
  if(AMISSL_INCLUDE_DIR AND AMISSL_STUBS_LIBRARY AND AMISSL_AUTO_LIBRARY)
    set(USE_AMISSL ON)
    list(APPEND CMAKE_REQUIRED_INCLUDES "${AMISSL_INCLUDE_DIR}")
    list(APPEND CMAKE_REQUIRED_LIBRARIES "${AMISSL_STUBS_LIBRARY}" "${AMISSL_AUTO_LIBRARY}")
    set(OPENSSL_INCLUDE_DIR "${AMISSL_INCLUDE_DIR}")
    set(OPENSSL_SSL_LIBRARY "${AMISSL_STUBS_LIBRARY}")
    set(OPENSSL_CRYPTO_LIBRARY "${AMISSL_AUTO_LIBRARY}")
    set(CURL_USE_OPENSSL ON)
    set(CURL_CA_FALLBACK ON CACHE BOOL "")
  endif()
elseif(NOT WIN32 AND NOT APPLE)
  check_library_exists("socket" "connect" "" HAVE_LIBSOCKET)
  if(HAVE_LIBSOCKET)
    set(CURL_LIBS "socket;${CURL_LIBS}")
  endif()
endif()

if(WIN32)
  list(APPEND CURL_LIBS "ws2_32" "bcrypt")
endif()

# Check SSL libraries
option(CURL_ENABLE_SSL "Enable SSL support" ON)

if(CURL_DEFAULT_SSL_BACKEND)
  set(_valid_default_ssl_backend FALSE)
endif()

if(APPLE)
  cmake_dependent_option(CURL_USE_SECTRANSP "Enable Apple OS native SSL/TLS (Secure Transport)" OFF CURL_ENABLE_SSL OFF)
endif()
if(WIN32)
  cmake_dependent_option(CURL_USE_SCHANNEL "Enable Windows native SSL/TLS (Schannel)" OFF CURL_ENABLE_SSL OFF)
  option(CURL_WINDOWS_SSPI "Enable SSPI on Windows" ${CURL_USE_SCHANNEL})
endif()
cmake_dependent_option(CURL_USE_MBEDTLS "Enable mbedTLS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_BEARSSL "Enable BearSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_WOLFSSL "Enable wolfSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_GNUTLS "Enable GnuTLS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_RUSTLS "Enable Rustls for SSL/TLS" OFF CURL_ENABLE_SSL OFF)

if(WIN32 OR
   CURL_USE_SECTRANSP OR
   CURL_USE_SCHANNEL OR
   CURL_USE_MBEDTLS OR
   CURL_USE_BEARSSL OR
   CURL_USE_WOLFSSL OR
   CURL_USE_GNUTLS OR
   CURL_USE_RUSTLS)
  set(_openssl_default OFF)
else()
  set(_openssl_default ON)
endif()
cmake_dependent_option(CURL_USE_OPENSSL "Enable OpenSSL for SSL/TLS" ${_openssl_default} CURL_ENABLE_SSL OFF)
option(USE_OPENSSL_QUIC "Use OpenSSL and nghttp3 libraries for HTTP/3 support" OFF)
if(USE_OPENSSL_QUIC AND NOT CURL_USE_OPENSSL)
  message(WARNING "OpenSSL QUIC has been requested, but without enabling OpenSSL. Will not enable QUIC.")
  set(USE_OPENSSL_QUIC OFF)
endif()
option(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG "Disable automatic loading of OpenSSL configuration" OFF)

curl_count_true(_enabled_ssl_options_count
  CURL_USE_SCHANNEL
  CURL_USE_SECTRANSP
  CURL_USE_OPENSSL
  CURL_USE_MBEDTLS
  CURL_USE_BEARSSL
  CURL_USE_WOLFSSL
  CURL_USE_GNUTLS
  CURL_USE_RUSTLS
)
if(_enabled_ssl_options_count GREATER 1)
  set(CURL_WITH_MULTI_SSL ON)
elseif(_enabled_ssl_options_count EQUAL 0)
  set(CURL_DISABLE_HSTS ON)
endif()

if(CURL_USE_SCHANNEL)
  set(_ssl_enabled ON)
  set(USE_SCHANNEL ON)  # Windows native SSL/TLS support
  set(USE_WINDOWS_SSPI ON)  # CURL_USE_SCHANNEL implies CURL_WINDOWS_SSPI

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "schannel")
    set(_valid_default_ssl_backend TRUE)
  endif()
endif()
if(CURL_WINDOWS_SSPI)
  set(USE_WINDOWS_SSPI ON)
endif()

if(CURL_USE_SECTRANSP)
  set(_use_core_foundation_and_core_services ON)

  find_library(SECURITY_FRAMEWORK NAMES "Security")
  mark_as_advanced(SECURITY_FRAMEWORK)
  if(NOT SECURITY_FRAMEWORK)
    message(FATAL_ERROR "Security framework not found")
  endif()
  list(APPEND CURL_LIBS "-framework Security")

  set(_ssl_enabled ON)
  set(USE_SECTRANSP ON)

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "secure-transport")
    set(_valid_default_ssl_backend TRUE)
  endif()

  message(WARNING "Secure Transport does not support TLS 1.3.")
endif()

if(_use_core_foundation_and_core_services)
  find_library(COREFOUNDATION_FRAMEWORK NAMES "CoreFoundation")
  mark_as_advanced(COREFOUNDATION_FRAMEWORK)
  if(NOT COREFOUNDATION_FRAMEWORK)
    message(FATAL_ERROR "CoreFoundation framework not found")
  endif()
  list(APPEND CURL_LIBS "-framework CoreFoundation")

  find_library(CORESERVICES_FRAMEWORK NAMES "CoreServices")
  mark_as_advanced(CORESERVICES_FRAMEWORK)
  if(NOT CORESERVICES_FRAMEWORK)
    message(FATAL_ERROR "CoreServices framework not found")
  endif()
  list(APPEND CURL_LIBS "-framework CoreServices")
endif()

if(CURL_USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  set(_ssl_enabled ON)
  set(USE_OPENSSL ON)

  # Depend on OpenSSL via imported targets. This allows our dependents to
  # get our dependencies transitively.
  list(APPEND CURL_LIBS OpenSSL::SSL OpenSSL::Crypto)
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE "openssl")

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "openssl")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)

  cmake_push_check_state()
  list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
  if(NOT DEFINED HAVE_BORINGSSL)
    check_symbol_exists("OPENSSL_IS_BORINGSSL" "openssl/base.h" HAVE_BORINGSSL)
  endif()
  if(NOT DEFINED HAVE_AWSLC)
    check_symbol_exists("OPENSSL_IS_AWSLC" "openssl/base.h" HAVE_AWSLC)
  endif()
  if(NOT DEFINED HAVE_LIBRESSL)
    check_symbol_exists("LIBRESSL_VERSION_NUMBER" "openssl/opensslv.h" HAVE_LIBRESSL)
  endif()
  cmake_pop_check_state()

  if(HAVE_BORINGSSL OR HAVE_AWSLC)
    if(OPENSSL_USE_STATIC_LIBS AND CMAKE_C_COMPILER_ID MATCHES "Clang")
      list(APPEND CURL_LIBS "stdc++")
      list(APPEND CMAKE_REQUIRED_LIBRARIES "stdc++")
    endif()
  endif()

  if(HAVE_BORINGSSL)
    set(_openssl "BoringSSL")
  elseif(HAVE_AWSLC)
    set(_openssl "AWS-LC")
  elseif(HAVE_LIBRESSL)
    set(_openssl "LibreSSL")
  elseif(USE_AMISSL)
    set(_openssl "AmiSSL")
  else()
    set(_openssl "OpenSSL")
    if(OPENSSL_VERSION VERSION_LESS 1.1.1)
      message(WARNING "OpenSSL ${OPENSSL_VERSION} does not support TLS 1.3.")
    endif()
  endif()
endif()

if(CURL_USE_MBEDTLS)
  find_package(MbedTLS REQUIRED)
  set(_ssl_enabled ON)
  set(USE_MBEDTLS ON)
  list(APPEND CURL_LIBS ${MBEDTLS_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${MBEDTLS_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${MBEDTLS_PC_REQUIRES})
  include_directories(SYSTEM ${MBEDTLS_INCLUDE_DIRS})
  link_directories(${MBEDTLS_LIBRARY_DIRS})
  if(MBEDTLS_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MBEDTLS_CFLAGS}")
  endif()

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "mbedtls")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)
endif()

if(CURL_USE_BEARSSL)
  find_package(BearSSL REQUIRED)
  set(_ssl_enabled ON)
  set(USE_BEARSSL ON)
  list(APPEND CURL_LIBS ${BEARSSL_LIBRARIES})
  include_directories(SYSTEM ${BEARSSL_INCLUDE_DIRS})

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "bearssl")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)

  message(WARNING "BearSSL does not support TLS 1.3.")
endif()

if(CURL_USE_WOLFSSL)
  find_package(WolfSSL REQUIRED)
  set(_ssl_enabled ON)
  set(USE_WOLFSSL ON)
  list(APPEND CURL_LIBS ${WOLFSSL_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${WOLFSSL_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${WOLFSSL_PC_REQUIRES})
  include_directories(SYSTEM ${WOLFSSL_INCLUDE_DIRS})
  link_directories(${WOLFSSL_LIBRARY_DIRS})
  if(WOLFSSL_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WOLFSSL_CFLAGS}")
  endif()

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "wolfssl")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)
endif()

if(CURL_USE_GNUTLS)
  if(CURL_USE_PKGCONFIG)
    find_package(PkgConfig QUIET)
    pkg_check_modules(GNUTLS "gnutls")
    if(GNUTLS_FOUND)
      set(GNUTLS_LIBRARIES ${GNUTLS_LINK_LIBRARIES})
    endif()
  endif()
  if(NOT GNUTLS_FOUND)
    find_package(GnuTLS REQUIRED)
  endif()
  find_package(Nettle REQUIRED)
  set(_ssl_enabled ON)
  set(USE_GNUTLS ON)
  list(APPEND CURL_LIBS ${GNUTLS_LIBRARIES} ${NETTLE_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${NETTLE_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE "gnutls" ${NETTLE_PC_REQUIRES})
  include_directories(SYSTEM ${GNUTLS_INCLUDE_DIRS} ${NETTLE_INCLUDE_DIRS})
  link_directories(${NETTLE_LIBRARY_DIRS})
  if(NETTLE_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NETTLE_CFLAGS}")
  endif()

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "gnutls")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)

  if(NOT DEFINED HAVE_GNUTLS_SRP AND NOT CURL_DISABLE_SRP)
    cmake_push_check_state()
    list(APPEND CMAKE_REQUIRED_INCLUDES ${GNUTLS_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${GNUTLS_LIBRARIES})
    check_symbol_exists("gnutls_srp_verifier" "gnutls/gnutls.h" HAVE_GNUTLS_SRP)
    cmake_pop_check_state()
  endif()
endif()

if(CURL_USE_RUSTLS)
  find_package(Rustls REQUIRED)
  set(_ssl_enabled ON)
  set(USE_RUSTLS ON)
  list(APPEND CURL_LIBS ${RUSTLS_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${RUSTLS_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${RUSTLS_PC_REQUIRES})
  include_directories(SYSTEM ${RUSTLS_INCLUDE_DIRS})
  link_directories(${RUSTLS_LIBRARY_DIRS})
  if(RUSTLS_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${RUSTLS_CFLAGS}")
  endif()

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "rustls")
    set(_valid_default_ssl_backend TRUE)
  endif()
  set(_curl_ca_bundle_supported TRUE)
endif()

if(CURL_DEFAULT_SSL_BACKEND AND NOT _valid_default_ssl_backend)
  message(FATAL_ERROR "CURL_DEFAULT_SSL_BACKEND '${CURL_DEFAULT_SSL_BACKEND}' not enabled.")
endif()

# Keep ZLIB detection after TLS detection,
# and before calling curl_openssl_check_symbol_exists().

set(HAVE_LIBZ OFF)
curl_dependency_option(CURL_ZLIB ZLIB "ZLIB")
if(ZLIB_FOUND)
  set(HAVE_LIBZ ON)
  # Depend on ZLIB via imported targets. This allows our dependents to
  # get our dependencies transitively.
  list(APPEND CURL_LIBS ZLIB::ZLIB)
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE "zlib")
endif()

set(HAVE_BROTLI OFF)
curl_dependency_option(CURL_BROTLI Brotli "brotli")
if(BROTLI_FOUND)
  set(HAVE_BROTLI ON)
  list(APPEND CURL_LIBS ${BROTLI_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${BROTLI_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${BROTLI_PC_REQUIRES})
  include_directories(SYSTEM ${BROTLI_INCLUDE_DIRS})
  link_directories(${BROTLI_LIBRARY_DIRS})
  if(BROTLI_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BROTLI_CFLAGS}")
  endif()
endif()

set(HAVE_ZSTD OFF)
curl_dependency_option(CURL_ZSTD Zstd "zstd")
if(ZSTD_FOUND)
  if(NOT ZSTD_VERSION VERSION_LESS 1.0.0)
    set(HAVE_ZSTD ON)
    list(APPEND CURL_LIBS ${ZSTD_LIBRARIES})
    list(APPEND CURL_LIBDIRS ${ZSTD_LIBRARY_DIRS})
    list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${ZSTD_PC_REQUIRES})
    include_directories(SYSTEM ${ZSTD_INCLUDE_DIRS})
    link_directories(${ZSTD_LIBRARY_DIRS})
    if(ZSTD_CFLAGS)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ZSTD_CFLAGS}")
    endif()
  else()
    message(WARNING "zstd v1.0.0 or newer is required, disabling zstd support.")
  endif()
endif()

# Check symbol in an OpenSSL-like TLS backend.
macro(curl_openssl_check_symbol_exists _symbol _files _variable)
  cmake_push_check_state()
  if(USE_OPENSSL)
    list(APPEND CMAKE_REQUIRED_INCLUDES   "${OPENSSL_INCLUDE_DIR}")
    list(APPEND CMAKE_REQUIRED_LIBRARIES  "${OPENSSL_LIBRARIES}")
    if(HAVE_LIBZ)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "${ZLIB_LIBRARIES}")
    endif()
    if(WIN32)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "ws2_32")
      list(APPEND CMAKE_REQUIRED_LIBRARIES "bcrypt")  # for OpenSSL/LibreSSL
    endif()
  endif()
  if(USE_WOLFSSL)
    list(APPEND CMAKE_REQUIRED_INCLUDES   "${WOLFSSL_INCLUDE_DIRS}")
    list(APPEND CMAKE_REQUIRED_LIBRARIES  "${WOLFSSL_LIBRARIES}")
    curl_required_libpaths("${WOLFSSL_LIBRARY_DIRS}")
    if(HAVE_LIBZ)
      list(APPEND CMAKE_REQUIRED_INCLUDES  "${ZLIB_INCLUDE_DIRS}")  # Public wolfSSL headers require zlib headers
      list(APPEND CMAKE_REQUIRED_LIBRARIES "${ZLIB_LIBRARIES}")
    endif()
    if(WIN32)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "ws2_32" "crypt32")
    endif()
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DHAVE_UINTPTR_T")  # to pull in stdint.h (as of wolfSSL v5.5.4)
  endif()
  check_symbol_exists("${_symbol}" "${_files}" "${_variable}")
  cmake_pop_check_state()
endmacro()

# Ensure that the OpenSSL fork actually supports QUIC.
macro(curl_openssl_check_quic)
  if(NOT DEFINED HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT)
    if(USE_OPENSSL)
      curl_openssl_check_symbol_exists("SSL_set_quic_use_legacy_codepoint" "openssl/ssl.h" HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT)
    endif()
    if(USE_WOLFSSL)
      curl_openssl_check_symbol_exists("wolfSSL_set_quic_use_legacy_codepoint" "wolfssl/options.h;wolfssl/openssl/ssl.h"
        HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT)
    endif()
  endif()
  if(NOT HAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT)
    message(FATAL_ERROR "QUIC support is missing in OpenSSL fork. Try setting -DOPENSSL_ROOT_DIR")
  endif()
endmacro()

if(USE_WOLFSSL)
  curl_openssl_check_symbol_exists("wolfSSL_DES_ecb_encrypt" "wolfssl/options.h;wolfssl/openssl/des.h" HAVE_WOLFSSL_DES_ECB_ENCRYPT)
  curl_openssl_check_symbol_exists("wolfSSL_BIO_new" "wolfssl/options.h;wolfssl/ssl.h" HAVE_WOLFSSL_BIO)
  curl_openssl_check_symbol_exists("wolfSSL_BIO_set_shutdown" "wolfssl/options.h;wolfssl/ssl.h" HAVE_WOLFSSL_FULL_BIO)
endif()

if(USE_OPENSSL OR USE_WOLFSSL)
  if(NOT DEFINED HAVE_SSL_SET0_WBIO)
    curl_openssl_check_symbol_exists("SSL_set0_wbio" "openssl/ssl.h" HAVE_SSL_SET0_WBIO)
  endif()
  if(NOT DEFINED HAVE_OPENSSL_SRP AND NOT CURL_DISABLE_SRP)
    curl_openssl_check_symbol_exists("SSL_CTX_set_srp_username" "openssl/ssl.h" HAVE_OPENSSL_SRP)
  endif()
endif()

option(USE_HTTPSRR "Enable HTTPS RR support" OFF)
option(USE_ECH "Enable ECH support" OFF)
if(USE_ECH)
  if(USE_OPENSSL OR USE_WOLFSSL)
    # Be sure that the TLS library actually supports ECH.
    if(USE_WOLFSSL)
      curl_openssl_check_symbol_exists("wolfSSL_CTX_GenerateEchConfig" "wolfssl/options.h;wolfssl/ssl.h"
        HAVE_WOLFSSL_CTX_GENERATEECHCONFIG)
    endif()
    if(HAVE_BORINGSSL OR HAVE_AWSLC)
      curl_openssl_check_symbol_exists("SSL_set1_ech_config_list" "openssl/ssl.h" HAVE_SSL_SET1_ECH_CONFIG_LIST)
    elseif(HAVE_OPENSSL)
      curl_openssl_check_symbol_exists("SSL_set1_ech_config_list" "openssl/ech.h" HAVE_SSL_SET1_ECH_CONFIG_LIST)
    endif()
    if(HAVE_WOLFSSL_CTX_GENERATEECHCONFIG OR
       HAVE_SSL_SET1_ECH_CONFIG_LIST)
      set(HAVE_ECH 1)
    endif()
    if(NOT HAVE_ECH)
      message(FATAL_ERROR "ECH support missing in OpenSSL/BoringSSL/AWS-LC/wolfSSL")
    else()
      message(STATUS "ECH enabled")
      # ECH wants HTTPSRR
      set(USE_HTTPSRR ON)
      message(STATUS "HTTPSRR enabled")
    endif()
  else()
    message(FATAL_ERROR "ECH requires ECH-enablded OpenSSL, BoringSSL, AWS-LC or wolfSSL")
  endif()
endif()

option(USE_SSLS_EXPORT "Enable SSL session export support" OFF)
if(USE_SSLS_EXPORT)
  if(_ssl_enabled)
    message(STATUS "SSL export enabled.")
  else()
    message(FATAL_ERROR "SSL session export requires SSL enabled")
  endif()
endif()

option(USE_NGHTTP2 "Use nghttp2 library" ON)
if(USE_NGHTTP2)
  find_package(NGHTTP2)
  if(NGHTTP2_FOUND)
    list(APPEND CURL_LIBS ${NGHTTP2_LIBRARIES})
    list(APPEND CURL_LIBDIRS ${NGHTTP2_LIBRARY_DIRS})
    list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${NGHTTP2_PC_REQUIRES})
    include_directories(SYSTEM ${NGHTTP2_INCLUDE_DIRS})
    link_directories(${NGHTTP2_LIBRARY_DIRS})
    if(NGHTTP2_CFLAGS)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NGHTTP2_CFLAGS}")
    endif()
  else()
    set(USE_NGHTTP2 OFF)
  endif()
endif()

option(USE_NGTCP2 "Use ngtcp2 and nghttp3 libraries for HTTP/3 support" OFF)
if(USE_NGTCP2)
  if(USE_OPENSSL OR USE_WOLFSSL)
    if(USE_WOLFSSL)
      find_package(NGTCP2 REQUIRED "wolfSSL")
    elseif(HAVE_BORINGSSL OR HAVE_AWSLC)
      find_package(NGTCP2 REQUIRED "BoringSSL")
    else()
      find_package(NGTCP2 REQUIRED "quictls")
      if(NOT HAVE_LIBRESSL)
        set(_openssl "quictls")
      endif()
    endif()
    curl_openssl_check_quic()
  elseif(USE_GNUTLS)
    find_package(NGTCP2 REQUIRED "GnuTLS")
  else()
    message(FATAL_ERROR "ngtcp2 requires OpenSSL, wolfSSL or GnuTLS")
  endif()
  list(APPEND CURL_LIBS ${NGTCP2_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${NGTCP2_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${NGTCP2_PC_REQUIRES})
  include_directories(SYSTEM ${NGTCP2_INCLUDE_DIRS})
  link_directories(${NGTCP2_LIBRARY_DIRS})
  if(NGTCP2_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NGTCP2_CFLAGS}")
  endif()

  find_package(NGHTTP3 REQUIRED)
  set(USE_NGHTTP3 ON)
  list(APPEND CURL_LIBS ${NGHTTP3_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${NGHTTP3_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${NGHTTP3_PC_REQUIRES})
  include_directories(SYSTEM ${NGHTTP3_INCLUDE_DIRS})
  link_directories(${NGHTTP3_LIBRARY_DIRS})
  if(NGHTTP3_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NGHTTP3_CFLAGS}")
  endif()
endif()

option(USE_QUICHE "Use quiche library for HTTP/3 support" OFF)
if(USE_QUICHE)
  if(USE_NGTCP2)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected")
  endif()
  find_package(Quiche REQUIRED)
  if(NOT HAVE_BORINGSSL)
    message(FATAL_ERROR "quiche requires BoringSSL")
  endif()
  curl_openssl_check_quic()
  list(APPEND CURL_LIBS ${QUICHE_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${QUICHE_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${QUICHE_PC_REQUIRES})
  include_directories(SYSTEM ${QUICHE_INCLUDE_DIRS})
  link_directories(${QUICHE_LIBRARY_DIRS})
  if(QUICHE_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUICHE_CFLAGS}")
  endif()
  if(NOT DEFINED HAVE_QUICHE_CONN_SET_QLOG_FD)
    cmake_push_check_state()
    list(APPEND CMAKE_REQUIRED_INCLUDES   "${QUICHE_INCLUDE_DIRS}")
    list(APPEND CMAKE_REQUIRED_LIBRARIES  "${QUICHE_LIBRARIES}")
    check_symbol_exists("quiche_conn_set_qlog_fd" "quiche.h" HAVE_QUICHE_CONN_SET_QLOG_FD)
    cmake_pop_check_state()
  endif()
endif()

option(USE_MSH3 "Use msh3/msquic library for HTTP/3 support" OFF)
if(USE_MSH3)
  if(USE_NGTCP2 OR USE_QUICHE)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected")
  endif()
  if(NOT WIN32)
    if(NOT USE_OPENSSL)
      message(FATAL_ERROR "msh3/msquic requires OpenSSL fork with QUIC API")
    endif()
    curl_openssl_check_quic()
  endif()
  find_package(MSH3 REQUIRED)
  list(APPEND CURL_LIBS ${MSH3_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${MSH3_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${MSH3_PC_REQUIRES})
  include_directories(SYSTEM ${MSH3_INCLUDE_DIRS})
  link_directories(${MSH3_LIBRARY_DIRS})
  if(MSH3_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MSH3_CFLAGS}")
  endif()
endif()

if(USE_OPENSSL_QUIC)
  if(USE_NGTCP2 OR USE_QUICHE OR USE_MSH3)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected")
  endif()
  find_package(OpenSSL 3.3.0 REQUIRED)

  find_package(NGHTTP3 REQUIRED)
  set(USE_NGHTTP3 ON)
  include_directories(SYSTEM ${NGHTTP3_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGHTTP3_LIBRARIES})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${NGHTTP3_PC_REQUIRES})
endif()

if(CURL_WITH_MULTI_SSL AND (USE_NGTCP2 OR USE_QUICHE OR USE_MSH3 OR USE_OPENSSL_QUIC))
  message(FATAL_ERROR "MultiSSL cannot be enabled with HTTP/3 and vice versa.")
endif()

if(NOT CURL_DISABLE_SRP AND (HAVE_GNUTLS_SRP OR HAVE_OPENSSL_SRP))
  set(USE_TLS_SRP 1)
endif()

if(NOT CURL_DISABLE_LDAP)
  if(WIN32 AND NOT WINDOWS_STORE)
    option(USE_WIN32_LDAP "Use Windows LDAP implementation" ON)
    if(USE_WIN32_LDAP)
      list(APPEND CURL_LIBS "wldap32")
      if(NOT CURL_DISABLE_LDAPS)
        set(HAVE_LDAP_SSL ON)
      endif()
    endif()
  endif()

  # Now that we know, we are not using Windows LDAP...
  if(NOT USE_WIN32_LDAP)
    # Check for LDAP
    cmake_push_check_state()
    if(USE_OPENSSL)
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    endif()
    find_package(LDAP)
    if(LDAP_FOUND)
      set(HAVE_LBER_H 1)
      set(CURL_LIBS "${LDAP_LIBRARIES};${CURL_LIBS}")
      list(APPEND CURL_LIBDIRS ${LDAP_LIBRARY_DIRS})
      if(LDAP_PC_REQUIRES)
        set(LIBCURL_PC_REQUIRES_PRIVATE "${LDAP_PC_REQUIRES};${LIBCURL_PC_REQUIRES_PRIVATE}")
      endif()
      include_directories(SYSTEM ${LDAP_INCLUDE_DIRS})
      link_directories(${LDAP_LIBRARY_DIRS})
      if(LDAP_CFLAGS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LDAP_CFLAGS}")
      endif()

      # LDAP feature checks

      list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DLDAP_DEPRECATED=1")
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${LDAP_LIBRARIES})
      curl_required_libpaths("${LDAP_LIBRARY_DIRS}")

      check_function_exists("ldap_url_parse" HAVE_LDAP_URL_PARSE)
      check_function_exists("ldap_init_fd" HAVE_LDAP_INIT_FD)

      check_include_file("ldap_ssl.h" HAVE_LDAP_SSL_H)

      if(HAVE_LDAP_INIT_FD)
        set(USE_OPENLDAP ON)
        add_definitions("-DLDAP_DEPRECATED=1")
      endif()
      if(NOT CURL_DISABLE_LDAPS)
        set(HAVE_LDAP_SSL ON)
      endif()
    else()
      message(STATUS "LDAP not found. CURL_DISABLE_LDAP set ON")
      set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
    endif()
    cmake_pop_check_state()
  endif()
endif()

# No ldap, no ldaps.
if(CURL_DISABLE_LDAP)
  if(NOT CURL_DISABLE_LDAPS)
    message(STATUS "LDAP needs to be enabled to support LDAPS")
    set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)
  endif()
endif()

if(WIN32)
  option(USE_WIN32_IDN "Use WinIDN for IDN support" OFF)
  if(USE_WIN32_IDN)
    list(APPEND CURL_LIBS "normaliz")
  endif()
else()
  set(USE_WIN32_IDN OFF)
endif()

if(APPLE)
  option(USE_APPLE_IDN "Use Apple built-in IDN support" OFF)
  if(USE_APPLE_IDN)
    cmake_push_check_state()
    list(APPEND CMAKE_REQUIRED_LIBRARIES "icucore")
    check_symbol_exists("uidna_openUTS46" "unicode/uidna.h" HAVE_APPLE_IDN)
    cmake_pop_check_state()
    if(HAVE_APPLE_IDN)
      list(APPEND CURL_LIBS "icucore" "iconv")
    else()
      set(USE_APPLE_IDN OFF)
    endif()
  endif()
else()
  set(USE_APPLE_IDN OFF)
endif()

# Check for libidn2
option(USE_LIBIDN2 "Use libidn2 for IDN support" ON)
set(HAVE_IDN2_H OFF)
set(HAVE_LIBIDN2 OFF)
if(USE_LIBIDN2 AND NOT USE_APPLE_IDN AND NOT USE_WIN32_IDN)
  find_package(Libidn2)
  if(LIBIDN2_FOUND)
    set(CURL_LIBS "${LIBIDN2_LIBRARIES};${CURL_LIBS}")
    list(APPEND CURL_LIBDIRS ${LIBIDN2_LIBRARY_DIRS})
    set(LIBCURL_PC_REQUIRES_PRIVATE "${LIBIDN2_PC_REQUIRES};${LIBCURL_PC_REQUIRES_PRIVATE}")
    include_directories(SYSTEM ${LIBIDN2_INCLUDE_DIRS})
    link_directories(${LIBIDN2_LIBRARY_DIRS})
    if(LIBIDN2_CFLAGS)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBIDN2_CFLAGS}")
    endif()
    set(HAVE_IDN2_H 1)
    set(HAVE_LIBIDN2 1)
  endif()
endif()

# libpsl
option(CURL_USE_LIBPSL "Use libpsl" ON)
mark_as_advanced(CURL_USE_LIBPSL)
set(USE_LIBPSL OFF)

if(CURL_USE_LIBPSL)
  find_package(Libpsl REQUIRED)
  list(APPEND CURL_LIBS ${LIBPSL_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${LIBPSL_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBPSL_PC_REQUIRES})
  include_directories(SYSTEM ${LIBPSL_INCLUDE_DIRS})
  link_directories(${LIBPSL_LIBRARY_DIRS})
  if(LIBPSL_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBPSL_CFLAGS}")
  endif()
  set(USE_LIBPSL ON)
endif()

# libssh2
option(CURL_USE_LIBSSH2 "Use libssh2" ON)
mark_as_advanced(CURL_USE_LIBSSH2)
set(USE_LIBSSH2 OFF)

if(CURL_USE_LIBSSH2)
  find_package(Libssh2)
  if(LIBSSH2_FOUND)
    list(APPEND CURL_LIBS ${LIBSSH2_LIBRARIES})
    list(APPEND CURL_LIBDIRS ${LIBSSH2_LIBRARY_DIRS})
    list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBSSH2_PC_REQUIRES})
    include_directories(SYSTEM ${LIBSSH2_INCLUDE_DIRS})
    link_directories(${LIBSSH2_LIBRARY_DIRS})
    if(LIBSSH2_CFLAGS)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBSSH2_CFLAGS}")
    endif()
    set(USE_LIBSSH2 ON)
  endif()
endif()

# libssh
option(CURL_USE_LIBSSH "Use libssh" OFF)
mark_as_advanced(CURL_USE_LIBSSH)
if(NOT USE_LIBSSH2 AND CURL_USE_LIBSSH)
  find_package(Libssh REQUIRED)
  list(APPEND CURL_LIBS ${LIBSSH_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${LIBSSH_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBSSH_PC_REQUIRES})
  include_directories(SYSTEM ${LIBSSH_INCLUDE_DIRS})
  link_directories(${LIBSSH_LIBRARY_DIRS})
  if(LIBSSH_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBSSH_CFLAGS}")
  endif()
  set(USE_LIBSSH ON)
endif()

# wolfSSH
option(CURL_USE_WOLFSSH "Use wolfSSH" OFF)
mark_as_advanced(CURL_USE_WOLFSSH)
set(USE_WOLFSSH OFF)
if(NOT USE_LIBSSH2 AND NOT USE_LIBSSH AND CURL_USE_WOLFSSH)
  if(USE_WOLFSSL)
    find_package(WolfSSH)
    if(WOLFSSH_FOUND)
      list(APPEND CURL_LIBS ${WOLFSSH_LIBRARIES})
      include_directories(SYSTEM ${WOLFSSH_INCLUDE_DIRS})
      set(USE_WOLFSSH ON)
    endif()
  else()
    message(WARNING "wolfSSH requires wolfSSL. Skipping.")
  endif()
endif()

option(CURL_USE_GSASL "Use libgsasl" OFF)
mark_as_advanced(CURL_USE_GSASL)
if(CURL_USE_GSASL)
  find_package(Libgsasl REQUIRED)
  list(APPEND CURL_LIBS ${LIBGSASL_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${LIBGSASL_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBGSASL_PC_REQUIRES})
  include_directories(SYSTEM ${LIBGSASL_INCLUDE_DIRS})
  link_directories(${LIBGSASL_LIBRARY_DIRS})
  if(LIBGSASL_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBGSASL_CFLAGS}")
  endif()
  set(USE_GSASL ON)
endif()

option(CURL_USE_GSSAPI "Use GSSAPI implementation" OFF)
mark_as_advanced(CURL_USE_GSSAPI)

if(CURL_USE_GSSAPI)
  find_package(GSS)

  set(HAVE_GSSAPI ${GSS_FOUND})
  if(GSS_FOUND)
    list(APPEND CURL_LIBS ${GSS_LIBRARIES})
    list(APPEND CURL_LIBDIRS ${GSS_LIBRARY_DIRS})
    list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${GSS_PC_REQUIRES})
    include_directories(SYSTEM ${GSS_INCLUDE_DIRS})
    link_directories(${GSS_LIBRARY_DIRS})
    if(GSS_CFLAGS)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GSS_CFLAGS}")
    endif()

    if(GSS_FLAVOUR STREQUAL "GNU")
      set(HAVE_GSSGNU 1)
    else()
      cmake_push_check_state()
      list(APPEND CMAKE_REQUIRED_INCLUDES ${GSS_INCLUDE_DIRS})

      set(_include_list "")
      check_include_file("gssapi/gssapi.h" HAVE_GSSAPI_GSSAPI_H)
      if(HAVE_GSSAPI_GSSAPI_H)
        list(APPEND _include_list "gssapi/gssapi.h")
      endif()
      check_include_files("${_include_list};gssapi/gssapi_generic.h" HAVE_GSSAPI_GSSAPI_GENERIC_H)

      if(GSS_FLAVOUR STREQUAL "MIT")
        check_include_files("${_include_list};gssapi/gssapi_krb5.h" _have_gssapi_gssapi_krb5_h)
        if(HAVE_GSSAPI_GSSAPI_GENERIC_H)
          list(APPEND _include_list "gssapi/gssapi_generic.h")
        endif()
        if(_have_gssapi_gssapi_krb5_h)
          list(APPEND _include_list "gssapi/gssapi_krb5.h")
        endif()

        if(NOT DEFINED HAVE_GSS_C_NT_HOSTBASED_SERVICE)
          set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${GSS_CFLAGS}")
          list(APPEND CMAKE_REQUIRED_LIBRARIES ${GSS_LIBRARIES})
          curl_required_libpaths("${GSS_LIBRARY_DIRS}")
          check_symbol_exists("GSS_C_NT_HOSTBASED_SERVICE" "${_include_list}" HAVE_GSS_C_NT_HOSTBASED_SERVICE)
        endif()
        if(NOT HAVE_GSS_C_NT_HOSTBASED_SERVICE)
          set(HAVE_OLD_GSSMIT ON)
        endif()
      endif()
      unset(_include_list)
      cmake_pop_check_state()
    endif()
  else()
    message(WARNING "GSSAPI has been requested, but no supporting libraries found. Skipping.")
  endif()
endif()

# libuv
option(CURL_USE_LIBUV "Use libuv for event-based tests" OFF)
if(CURL_USE_LIBUV)
  if(NOT ENABLE_DEBUG)
    message(FATAL_ERROR "Using libuv without debug support enabled is useless")
  endif()
  find_package(Libuv REQUIRED)
  list(APPEND CURL_LIBS ${LIBUV_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${LIBUV_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBUV_PC_REQUIRES})
  include_directories(SYSTEM ${LIBUV_INCLUDE_DIRS})
  link_directories(${LIBUV_LIBRARY_DIRS})
  if(LIBUV_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBUV_CFLAGS}")
  endif()
  set(USE_LIBUV ON)
  set(HAVE_UV_H ON)
endif()

option(USE_LIBRTMP "Enable librtmp from rtmpdump" OFF)
if(USE_LIBRTMP)
  find_package(Librtmp REQUIRED)
  list(APPEND CURL_LIBS ${LIBRTMP_LIBRARIES})
  list(APPEND CURL_LIBDIRS ${LIBRTMP_LIBRARY_DIRS})
  list(APPEND LIBCURL_PC_REQUIRES_PRIVATE ${LIBRTMP_PC_REQUIRES})
  include_directories(SYSTEM ${LIBRTMP_INCLUDE_DIRS})
  link_directories(${LIBRTMP_LIBRARY_DIRS})
  if(LIBRTMP_CFLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBRTMP_CFLAGS}")
  endif()
endif()

option(ENABLE_UNIX_SOCKETS "Enable Unix domain sockets support" ON)
if(ENABLE_UNIX_SOCKETS)
  if(WIN32 OR DOS)
    set(USE_UNIX_SOCKETS ON)
  else()
    include(CheckStructHasMember)
    check_struct_has_member("struct sockaddr_un" "sun_path" "sys/un.h" USE_UNIX_SOCKETS)
  endif()
else()
  unset(USE_UNIX_SOCKETS CACHE)
endif()

#
# CA handling
#
if(_curl_ca_bundle_supported)
  set(CURL_CA_BUNDLE "auto" CACHE
    STRING "Path to the CA bundle. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
  set(CURL_CA_FALLBACK OFF CACHE
    BOOL "Use built-in CA store of TLS backend. Defaults to OFF")
  set(CURL_CA_PATH "auto" CACHE
    STRING "Location of default CA path. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
  set(CURL_CA_EMBED "" CACHE
    STRING "Path to the CA bundle to embed in the curl tool.")

  if(CURL_CA_BUNDLE STREQUAL "")
    message(FATAL_ERROR "Invalid value of CURL_CA_BUNDLE. Use 'none', 'auto' or file path.")
  elseif(CURL_CA_BUNDLE STREQUAL "none")
    unset(CURL_CA_BUNDLE CACHE)
  elseif(CURL_CA_BUNDLE STREQUAL "auto")
    unset(CURL_CA_BUNDLE CACHE)
    if(NOT CMAKE_CROSSCOMPILING AND NOT WIN32)
      set(_curl_ca_bundle_autodetect TRUE)
    endif()
  else()
    set(CURL_CA_BUNDLE_SET TRUE)
  endif()
  mark_as_advanced(CURL_CA_BUNDLE_SET)

  if(CURL_CA_PATH STREQUAL "")
    message(FATAL_ERROR "Invalid value of CURL_CA_PATH. Use 'none', 'auto' or directory path.")
  elseif(CURL_CA_PATH STREQUAL "none")
    unset(CURL_CA_PATH CACHE)
  elseif(CURL_CA_PATH STREQUAL "auto")
    unset(CURL_CA_PATH CACHE)
    if(NOT CMAKE_CROSSCOMPILING AND NOT WIN32)
      set(_curl_ca_path_autodetect TRUE)
    endif()
  else()
    set(CURL_CA_PATH_SET TRUE)
  endif()
  mark_as_advanced(CURL_CA_PATH_SET)

  if(CURL_CA_BUNDLE_SET AND _curl_ca_path_autodetect)
    # Skip auto-detection of unset CA path because CA bundle is set explicitly
  elseif(CURL_CA_PATH_SET AND _curl_ca_bundle_autodetect)
    # Skip auto-detection of unset CA bundle because CA path is set explicitly
  elseif(_curl_ca_bundle_autodetect OR _curl_ca_path_autodetect)
    # First try auto-detecting a CA bundle, then a CA path

    if(_curl_ca_bundle_autodetect)
      foreach(_search_ca_bundle_path IN ITEMS
          "/etc/ssl/certs/ca-certificates.crt"
          "/etc/pki/tls/certs/ca-bundle.crt"
          "/usr/share/ssl/certs/ca-bundle.crt"
          "/usr/local/share/certs/ca-root-nss.crt"
          "/etc/ssl/cert.pem")
        if(EXISTS "${_search_ca_bundle_path}")
          message(STATUS "Found CA bundle: ${_search_ca_bundle_path}")
          set(CURL_CA_BUNDLE "${_search_ca_bundle_path}" CACHE
            STRING "Path to the CA bundle. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
          set(CURL_CA_BUNDLE_SET TRUE CACHE BOOL "Path to the CA bundle has been set")
          break()
        endif()
      endforeach()
    endif()

    if(_curl_ca_path_autodetect AND NOT CURL_CA_PATH_SET)
      set(_search_ca_path "/etc/ssl/certs")
      file(GLOB _curl_ca_files_found "${_search_ca_path}/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].0")
      if(_curl_ca_files_found)
        unset(_curl_ca_files_found)
        message(STATUS "Found CA path: ${_search_ca_path}")
        set(CURL_CA_PATH "${_search_ca_path}" CACHE
          STRING "Location of default CA path. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
        set(CURL_CA_PATH_SET TRUE CACHE BOOL "Path to the CA bundle has been set")
      endif()
    endif()
  endif()

  set(CURL_CA_EMBED_SET FALSE)
  if(BUILD_CURL_EXE AND NOT CURL_CA_EMBED STREQUAL "")
    if(EXISTS "${CURL_CA_EMBED}")
      set(CURL_CA_EMBED_SET TRUE)
      message(STATUS "Found CA bundle to embed: ${CURL_CA_EMBED}")
    else()
      message(FATAL_ERROR "CA bundle to embed is missing: '${CURL_CA_EMBED}'")
    endif()
  endif()
endif()

if(WIN32)
  option(CURL_DISABLE_CA_SEARCH "Disable unsafe CA bundle search in PATH on Windows" OFF)
  option(CURL_CA_SEARCH_SAFE "Enable safe CA bundle search (within the curl tool directory) on Windows" OFF)
endif()

# Check for header files
if(WIN32)
  list(APPEND CURL_INCLUDES "winsock2.h")
  list(APPEND CURL_INCLUDES "ws2tcpip.h")

  if(HAVE_WIN32_WINNT)
    if(HAVE_WIN32_WINNT LESS 0x0501)
      # Windows XP is required for freeaddrinfo, getaddrinfo
      message(FATAL_ERROR "Building for Windows XP or newer is required.")
    endif()

    # Pre-fill detection results based on target OS version
    if(MINGW OR MSVC)
      if(HAVE_WIN32_WINNT LESS 0x0600)
        set(HAVE_INET_NTOP 0)
        set(HAVE_INET_PTON 0)
      else()  # Windows Vista or newer
        set(HAVE_INET_NTOP 1)
        set(HAVE_INET_PTON 1)
      endif()
      unset(HAVE_INET_NTOP CACHE)
      unset(HAVE_INET_PTON CACHE)
    endif()
  endif()
endif()

# Detect headers

# Use check_include_file_concat_curl() for headers required by subsequent
# check_include_file_concat_curl() or check_symbol_exists() detections.
# Order for these is significant.
check_include_file("sys/eventfd.h"    HAVE_SYS_EVENTFD_H)
check_include_file("sys/filio.h"      HAVE_SYS_FILIO_H)
check_include_file("sys/ioctl.h"      HAVE_SYS_IOCTL_H)
check_include_file("sys/param.h"      HAVE_SYS_PARAM_H)
check_include_file("sys/poll.h"       HAVE_SYS_POLL_H)
check_include_file("sys/resource.h"   HAVE_SYS_RESOURCE_H)
check_include_file_concat_curl("sys/select.h"     HAVE_SYS_SELECT_H)
check_include_file_concat_curl("sys/socket.h"     HAVE_SYS_SOCKET_H)
check_include_file("sys/sockio.h"     HAVE_SYS_SOCKIO_H)
check_include_file("sys/stat.h"       HAVE_SYS_STAT_H)
check_include_file_concat_curl("sys/time.h"       HAVE_SYS_TIME_H)
check_include_file_concat_curl("sys/types.h"      HAVE_SYS_TYPES_H)
check_include_file("sys/un.h"         HAVE_SYS_UN_H)
check_include_file_concat_curl("sys/utime.h"      HAVE_SYS_UTIME_H)  # sys/types.h (AmigaOS)

check_include_file_concat_curl("arpa/inet.h"      HAVE_ARPA_INET_H)
check_include_file("dirent.h"         HAVE_DIRENT_H)
check_include_file("fcntl.h"          HAVE_FCNTL_H)
check_include_file_concat_curl("ifaddrs.h"        HAVE_IFADDRS_H)
check_include_file("io.h"             HAVE_IO_H)
check_include_file_concat_curl("libgen.h"         HAVE_LIBGEN_H)
check_include_file("linux/tcp.h"      HAVE_LINUX_TCP_H)
check_include_file("locale.h"         HAVE_LOCALE_H)
check_include_file_concat_curl("net/if.h"         HAVE_NET_IF_H)  # sys/select.h (e.g. MS-DOS/Watt-32)
check_include_file_concat_curl("netdb.h"          HAVE_NETDB_H)
check_include_file_concat_curl("netinet/in.h"     HAVE_NETINET_IN_H)
check_include_file("netinet/in6.h"    HAVE_NETINET_IN6_H)
check_include_file_concat_curl("netinet/tcp.h"    HAVE_NETINET_TCP_H)  # sys/types.h (e.g. Cygwin) netinet/in.h
check_include_file_concat_curl("netinet/udp.h"    HAVE_NETINET_UDP_H)  # sys/types.h (e.g. Cygwin)
check_include_file("poll.h"           HAVE_POLL_H)
check_include_file("pwd.h"            HAVE_PWD_H)
check_include_file("stdatomic.h"      HAVE_STDATOMIC_H)
check_include_file("stdbool.h"        HAVE_STDBOOL_H)
check_include_file("strings.h"        HAVE_STRINGS_H)
check_include_file("stropts.h"        HAVE_STROPTS_H)
check_include_file("termio.h"         HAVE_TERMIO_H)
check_include_file("termios.h"        HAVE_TERMIOS_H)
check_include_file_concat_curl("unistd.h"         HAVE_UNISTD_H)
check_include_file("utime.h"          HAVE_UTIME_H)

if(AMIGA)
  check_include_file_concat_curl("proto/bsdsocket.h" HAVE_PROTO_BSDSOCKET_H)
endif()

# Pass these detection results to curl_internal_test() for use in CurlTests.c
# Add here all feature flags referenced from CurlTests.c
foreach(_variable IN ITEMS
    HAVE_STDATOMIC_H
    HAVE_STDBOOL_H
    HAVE_STROPTS_H
    HAVE_SYS_IOCTL_H
    HAVE_SYS_SOCKET_H
    HAVE_SYS_TYPES_H
    HAVE_UNISTD_H
    )
  if(${_variable})
    set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -D${_variable}")
  endif()
endforeach()

check_type_size("size_t"      SIZEOF_SIZE_T)
check_type_size("ssize_t"     SIZEOF_SSIZE_T)
check_type_size("long long"   SIZEOF_LONG_LONG)
check_type_size("long"        SIZEOF_LONG)
check_type_size("int"         SIZEOF_INT)
check_type_size("__int64"     SIZEOF___INT64)
check_type_size("time_t"      SIZEOF_TIME_T)
check_type_size("suseconds_t" SIZEOF_SUSECONDS_T)
if(NOT HAVE_SIZEOF_SSIZE_T)
  if(SIZEOF_LONG EQUAL SIZEOF_SIZE_T)
    set(ssize_t "long")
  endif()
  if(NOT ssize_t AND SIZEOF___INT64 EQUAL SIZEOF_SIZE_T)
    set(ssize_t "__int64")
  endif()
endif()
# off_t is sized later, after the HAVE_FILE_OFFSET_BITS test

if(SIZEOF_LONG_LONG)
  set(HAVE_LONGLONG 1)
endif()
if(SIZEOF_SUSECONDS_T)
  set(HAVE_SUSECONDS_T 1)
endif()

# Check for some functions that are used

# Apply to all feature checks
if(WIN32)
  list(APPEND CMAKE_REQUIRED_LIBRARIES "ws2_32")
elseif(HAVE_LIBSOCKET)
  list(APPEND CMAKE_REQUIRED_LIBRARIES "socket")
elseif(DOS)
  list(APPEND CMAKE_REQUIRED_LIBRARIES "${WATT_ROOT}/lib/libwatt.a")
endif()

check_function_exists("fnmatch"       HAVE_FNMATCH)
check_symbol_exists("basename"        "${CURL_INCLUDES};string.h" HAVE_BASENAME)  # libgen.h unistd.h
check_symbol_exists("opendir"         "dirent.h" HAVE_OPENDIR)
check_function_exists("poll"          HAVE_POLL)  # poll.h
check_symbol_exists("socket"          "${CURL_INCLUDES}" HAVE_SOCKET)  # winsock2.h sys/socket.h
check_symbol_exists("socketpair"      "${CURL_INCLUDES}" HAVE_SOCKETPAIR)  # sys/socket.h
check_symbol_exists("recv"            "${CURL_INCLUDES}" HAVE_RECV)  # proto/bsdsocket.h sys/types.h sys/socket.h
check_symbol_exists("send"            "${CURL_INCLUDES}" HAVE_SEND)  # proto/bsdsocket.h sys/types.h sys/socket.h
check_function_exists("sendmsg"       HAVE_SENDMSG)
check_function_exists("sendmmsg"      HAVE_SENDMMSG)
check_symbol_exists("select"          "${CURL_INCLUDES}" HAVE_SELECT)  # proto/bsdsocket.h sys/select.h sys/socket.h
check_symbol_exists("strdup"          "string.h" HAVE_STRDUP)
check_symbol_exists("strtok_r"        "string.h" HAVE_STRTOK_R)
check_symbol_exists("memrchr"         "string.h" HAVE_MEMRCHR)
check_symbol_exists("alarm"           "unistd.h" HAVE_ALARM)
check_symbol_exists("fcntl"           "fcntl.h" HAVE_FCNTL)
check_function_exists("getppid"       HAVE_GETPPID)
check_function_exists("utimes"        HAVE_UTIMES)

check_function_exists("gettimeofday"  HAVE_GETTIMEOFDAY)  # sys/time.h
check_symbol_exists("closesocket"     "${CURL_INCLUDES}" HAVE_CLOSESOCKET)  # winsock2.h
check_symbol_exists("sigsetjmp"       "setjmp.h" HAVE_SIGSETJMP)
check_function_exists("getpass_r"     HAVE_GETPASS_R)
check_function_exists("getpwuid"      HAVE_GETPWUID)
check_function_exists("getpwuid_r"    HAVE_GETPWUID_R)
check_function_exists("geteuid"       HAVE_GETEUID)
check_function_exists("utime"         HAVE_UTIME)
check_symbol_exists("gmtime_r"        "stdlib.h;time.h" HAVE_GMTIME_R)

check_symbol_exists("gethostbyname_r" "netdb.h" HAVE_GETHOSTBYNAME_R)
check_symbol_exists("gethostname"     "${CURL_INCLUDES}" HAVE_GETHOSTNAME)  # winsock2.h unistd.h proto/bsdsocket.h

check_symbol_exists("signal"          "signal.h" HAVE_SIGNAL)
check_symbol_exists("strtoll"         "stdlib.h" HAVE_STRTOLL)
check_symbol_exists("strerror_r"      "stdlib.h;string.h" HAVE_STRERROR_R)
check_symbol_exists("sigaction"       "signal.h" HAVE_SIGACTION)
check_symbol_exists("siginterrupt"    "signal.h" HAVE_SIGINTERRUPT)
check_symbol_exists("getaddrinfo"     "${CURL_INCLUDES};stdlib.h;string.h" HAVE_GETADDRINFO)  # ws2tcpip.h sys/socket.h netdb.h
check_symbol_exists("getifaddrs"      "${CURL_INCLUDES};stdlib.h" HAVE_GETIFADDRS)  # ifaddrs.h
check_symbol_exists("freeaddrinfo"    "${CURL_INCLUDES}" HAVE_FREEADDRINFO)  # ws2tcpip.h sys/socket.h netdb.h
check_function_exists("pipe"          HAVE_PIPE)
check_function_exists("eventfd"       HAVE_EVENTFD)
check_symbol_exists("ftruncate"       "unistd.h" HAVE_FTRUNCATE)
check_symbol_exists("getpeername"     "${CURL_INCLUDES}" HAVE_GETPEERNAME)  # winsock2.h unistd.h proto/bsdsocket.h
check_symbol_exists("getsockname"     "${CURL_INCLUDES}" HAVE_GETSOCKNAME)  # winsock2.h unistd.h proto/bsdsocket.h
check_function_exists("if_nametoindex"  HAVE_IF_NAMETOINDEX)  # winsock2.h net/if.h
check_function_exists("getrlimit"       HAVE_GETRLIMIT)
check_function_exists("setlocale"       HAVE_SETLOCALE)
check_function_exists("setmode"         HAVE_SETMODE)
check_function_exists("setrlimit"       HAVE_SETRLIMIT)

if(NOT WIN32)
  check_function_exists("sched_yield"   HAVE_SCHED_YIELD)
  check_symbol_exists("strcasecmp"      "string.h" HAVE_STRCASECMP)
  check_symbol_exists("stricmp"         "string.h" HAVE_STRICMP)
  check_symbol_exists("strcmpi"         "string.h" HAVE_STRCMPI)
endif()

if(WIN32 OR CYGWIN)
  check_function_exists("_setmode" HAVE__SETMODE)
endif()

if(AMIGA)
  check_symbol_exists("CloseSocket" "${CURL_INCLUDES}" HAVE_CLOSESOCKET_CAMEL)  # sys/socket.h proto/bsdsocket.h
endif()

if(NOT _ssl_enabled)
  check_symbol_exists("arc4random" "${CURL_INCLUDES};stdlib.h" HAVE_ARC4RANDOM)
endif()

if(NOT MSVC OR (MSVC_VERSION GREATER_EQUAL 1900))
  # Earlier MSVC compilers had faulty snprintf implementations
  check_function_exists("snprintf" HAVE_SNPRINTF)
endif()
if(APPLE)
  check_function_exists("mach_absolute_time" HAVE_MACH_ABSOLUTE_TIME)
endif()
check_symbol_exists("inet_ntop" "${CURL_INCLUDES};stdlib.h;string.h" HAVE_INET_NTOP)  # arpa/inet.h
check_symbol_exists("inet_pton" "${CURL_INCLUDES};stdlib.h;string.h" HAVE_INET_PTON)  # arpa/inet.h

check_symbol_exists("fsetxattr" "sys/xattr.h" HAVE_FSETXATTR)
if(HAVE_FSETXATTR)
  curl_internal_test(HAVE_FSETXATTR_5)
  curl_internal_test(HAVE_FSETXATTR_6)
endif()

cmake_push_check_state()
if(WIN32)
  list(APPEND CMAKE_EXTRA_INCLUDE_FILES "winsock2.h")
  check_type_size("ADDRESS_FAMILY" SIZEOF_ADDRESS_FAMILY)
  set(HAVE_ADDRESS_FAMILY ${HAVE_SIZEOF_ADDRESS_FAMILY})
elseif(HAVE_SYS_SOCKET_H)
  list(APPEND CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
  check_type_size("sa_family_t" SIZEOF_SA_FAMILY_T)
  set(HAVE_SA_FAMILY_T ${HAVE_SIZEOF_SA_FAMILY_T})
endif()
cmake_pop_check_state()

# Do curl specific tests
foreach(_curl_test IN ITEMS
    HAVE_FCNTL_O_NONBLOCK
    HAVE_IOCTLSOCKET
    HAVE_IOCTLSOCKET_CAMEL
    HAVE_IOCTLSOCKET_CAMEL_FIONBIO
    HAVE_IOCTLSOCKET_FIONBIO
    HAVE_IOCTL_FIONBIO
    HAVE_IOCTL_SIOCGIFADDR
    HAVE_SETSOCKOPT_SO_NONBLOCK
    HAVE_GETHOSTBYNAME_R_3
    HAVE_GETHOSTBYNAME_R_5
    HAVE_GETHOSTBYNAME_R_6
    HAVE_GETHOSTBYNAME_R_3_REENTRANT
    HAVE_GETHOSTBYNAME_R_5_REENTRANT
    HAVE_GETHOSTBYNAME_R_6_REENTRANT
    HAVE_IN_ADDR_T
    HAVE_BOOL_T
    STDC_HEADERS
    HAVE_FILE_OFFSET_BITS
    HAVE_ATOMIC
    )
  curl_internal_test(${_curl_test})
endforeach()

cmake_push_check_state()
if(HAVE_FILE_OFFSET_BITS)
  set(_FILE_OFFSET_BITS 64)
  list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_FILE_OFFSET_BITS=64")
endif()
check_type_size("off_t" SIZEOF_OFF_T)

if(NOT WIN32)
  # fseeko may not exist with _FILE_OFFSET_BITS=64 but can exist with
  # _FILE_OFFSET_BITS unset or 32 (e.g. Android ARMv7 with NDK 26b and API level < 24)
  # so we need to test fseeko after testing for _FILE_OFFSET_BITS
  check_symbol_exists("fseeko" "${CURL_INCLUDES};stdio.h" HAVE_FSEEKO)

  if(HAVE_FSEEKO)
    set(HAVE_DECL_FSEEKO 1)
  endif()
endif()

# Include this header to get the type
cmake_push_check_state()
list(APPEND CMAKE_REQUIRED_INCLUDES "${PROJECT_SOURCE_DIR}/include")
list(APPEND CMAKE_EXTRA_INCLUDE_FILES "curl/system.h")
check_type_size("curl_off_t" SIZEOF_CURL_OFF_T)
list(APPEND CMAKE_EXTRA_INCLUDE_FILES "curl/curl.h")
check_type_size("curl_socket_t" SIZEOF_CURL_SOCKET_T)
cmake_pop_check_state()  # pop curl system headers
cmake_pop_check_state()  # pop -D_FILE_OFFSET_BITS=64

if(NOT WIN32 AND NOT CMAKE_CROSSCOMPILING)
  # On non-Windows and not cross-compiling, check for writable argv[]
  include(CheckCSourceRuns)
  check_c_source_runs("
    int main(int argc, char **argv)
    {
      (void)argc;
      argv[0][0] = ' ';
      return (argv[0][0] == ' ')?0:1;
    }" HAVE_WRITABLE_ARGV)
endif()

if(NOT CMAKE_CROSSCOMPILING)
  include(CheckCSourceRuns)
  check_c_source_runs("
    #include <time.h>
    int main(void) {
      time_t t = -1;
      return t < 0;
    }" HAVE_TIME_T_UNSIGNED)
endif()

curl_internal_test(HAVE_GLIBC_STRERROR_R)
curl_internal_test(HAVE_POSIX_STRERROR_R)

# Check for reentrant
foreach(_curl_test IN ITEMS
    HAVE_GETHOSTBYNAME_R_3
    HAVE_GETHOSTBYNAME_R_5
    HAVE_GETHOSTBYNAME_R_6)
  if(NOT ${_curl_test})
    if(${_curl_test}_REENTRANT)
      set(NEED_REENTRANT 1)
    endif()
  endif()
endforeach()

if(NEED_REENTRANT)
  foreach(_curl_test IN ITEMS
      HAVE_GETHOSTBYNAME_R_3
      HAVE_GETHOSTBYNAME_R_5
      HAVE_GETHOSTBYNAME_R_6)
    set(${_curl_test} 0)
    if(${_curl_test}_REENTRANT)
      set(${_curl_test} 1)
    endif()
  endforeach()
endif()

if(NOT WIN32)
  curl_internal_test(HAVE_CLOCK_GETTIME_MONOTONIC)  # Check clock_gettime(CLOCK_MONOTONIC, x) support
endif()

if(APPLE)
  curl_internal_test(HAVE_BUILTIN_AVAILABLE)  # Check compiler support of __builtin_available()
endif()

# Some other minor tests

if(NOT HAVE_IN_ADDR_T)
  set(in_addr_t "unsigned long")
endif()

if(CMAKE_COMPILER_IS_GNUCC AND APPLE)
  include(CheckCCompilerFlag)
  check_c_compiler_flag("-Wno-long-double" HAVE_C_FLAG_Wno_long_double)
  if(HAVE_C_FLAG_Wno_long_double)
    # The Mac version of GCC warns about use of long double. Disable it.
    get_source_file_property(_mprintf_compile_flags "mprintf.c" COMPILE_FLAGS)
    if(_mprintf_compile_flags)
      set(_mprintf_compile_flags "${_mprintf_compile_flags} -Wno-long-double")
    else()
      set(_mprintf_compile_flags "-Wno-long-double")
    endif()
    set_source_files_properties("mprintf.c" PROPERTIES
      COMPILE_FLAGS ${_mprintf_compile_flags})
  endif()
endif()

if(_cmake_try_compile_target_type_save)
  set(CMAKE_TRY_COMPILE_TARGET_TYPE ${_cmake_try_compile_target_type_save})
  unset(_cmake_try_compile_target_type_save)
endif()

include(CMake/OtherTests.cmake)

add_definitions("-DHAVE_CONFIG_H")

if(WIN32)
  # _fseeki64() requires VS2005
  if(NOT MSVC OR (MSVC_VERSION GREATER_EQUAL 1400))
    set(USE_WIN32_LARGE_FILES ON)
  endif()

  # Use the manifest embedded in the Windows Resource
  set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -DCURL_EMBED_MANIFEST")

  # We use crypto functions that are not available for UWP apps
  if(NOT WINDOWS_STORE)
    set(USE_WIN32_CRYPTO ON)
  endif()

  # Link required libraries for USE_WIN32_CRYPTO or USE_SCHANNEL
  if(USE_WIN32_CRYPTO OR USE_SCHANNEL)
    list(APPEND CURL_LIBS "advapi32" "crypt32")
  endif()
endif()

if(MSVC)
  # Disable default manifest added by CMake
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -MANIFEST:NO")

  if(CMAKE_C_FLAGS MATCHES "[/-]W[0-4]")
    string(REGEX REPLACE "[/-]W[0-4]" "-W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W4")
  endif()

  # Use multithreaded compilation on VS2008+
  if(CMAKE_C_COMPILER_ID STREQUAL "MSVC" AND MSVC_VERSION GREATER_EQUAL 1500)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -MP")
  endif()
endif()

if(CURL_WERROR)
  if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -WX")
  else()
    # This assumes clang or gcc style options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
  endif()
endif()

if(CURL_LTO)
  if(CMAKE_VERSION VERSION_LESS 3.9)
    message(FATAL_ERROR "LTO has been requested, but your cmake version ${CMAKE_VERSION} is to old. You need at least 3.9")
  endif()

  cmake_policy(SET CMP0069 NEW)

  include(CheckIPOSupported)
  check_ipo_supported(RESULT CURL_HAS_LTO OUTPUT _lto_error LANGUAGES C)
  if(CURL_HAS_LTO)
    message(STATUS "LTO supported and enabled")
  else()
    message(FATAL_ERROR "LTO has been requested, but the compiler does not support it\n${_lto_error}")
  endif()
endif()


# Ugly (but functional) way to include "Makefile.inc" by transforming it
# (= regenerate it).
function(curl_transform_makefile_inc _input_file _output_file)
  file(READ ${_input_file} _makefile_inc_text)
  string(REPLACE "$(top_srcdir)"   "\${PROJECT_SOURCE_DIR}" _makefile_inc_text ${_makefile_inc_text})
  string(REPLACE "$(top_builddir)" "\${PROJECT_BINARY_DIR}" _makefile_inc_text ${_makefile_inc_text})

  string(REGEX REPLACE "\\\\\n" "!π!α!" _makefile_inc_text ${_makefile_inc_text})
  string(REGEX REPLACE "([a-zA-Z_][a-zA-Z0-9_]*)[\t ]*=[\t ]*([^\n]*)" "set(\\1 \\2)" _makefile_inc_text ${_makefile_inc_text})
  string(REPLACE "!π!α!" "\n" _makefile_inc_text ${_makefile_inc_text})

  # Replace $() with ${}
  string(REGEX REPLACE "\\$\\(([a-zA-Z_][a-zA-Z0-9_]*)\\)" "\${\\1}" _makefile_inc_text ${_makefile_inc_text})
  # Replace @@ with ${}, even if that may not be read by CMake scripts.
  string(REGEX REPLACE "@([a-zA-Z_][a-zA-Z0-9_]*)@" "\${\\1}" _makefile_inc_text ${_makefile_inc_text})

  file(WRITE ${_output_file} ${_makefile_inc_text})
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_input_file}")
endfunction()

include(GNUInstallDirs)

set(_install_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(_project_config "${_generated_dir}/${PROJECT_NAME}Config.cmake")
set(_version_config "${_generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")

option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING AND PERL_FOUND AND NOT CURL_DISABLE_TESTS)
  set(CURL_BUILD_TESTING ON)
else()
  set(CURL_BUILD_TESTING OFF)
endif()

if(HAVE_MANUAL_TOOLS)
  set(CURL_MANPAGE "${PROJECT_BINARY_DIR}/docs/cmdline-opts/curl.1")
  set(CURL_ASCIIPAGE "${PROJECT_BINARY_DIR}/docs/cmdline-opts/curl.txt")
  add_subdirectory(docs)
endif()

add_subdirectory(lib)

if(BUILD_CURL_EXE)
  add_subdirectory(src)
endif()

option(BUILD_EXAMPLES "Build libcurl examples" ON)
if(BUILD_EXAMPLES)
  add_subdirectory(docs/examples)
endif()

if(CURL_BUILD_TESTING)
  add_subdirectory(tests)
endif()

# Helper to populate a list (_items) with a label when conditions
# (the remaining args) are satisfied
macro(curl_add_if _label)
  # Needs to be a macro to allow this indirection
  if(${ARGN})
    set(_items ${_items} "${_label}")
  endif()
endmacro()

# NTLM support requires crypto functions from various SSL libs.
# These conditions must match those in lib/curl_setup.h.
if(NOT CURL_DISABLE_NTLM AND
   (USE_OPENSSL OR
    USE_MBEDTLS OR
    USE_GNUTLS OR
    USE_SECTRANSP OR
    USE_WIN32_CRYPTO OR
    (USE_WOLFSSL AND HAVE_WOLFSSL_DES_ECB_ENCRYPT)))
  set(_use_curl_ntlm_core ON)
endif()

# Clear list and try to detect available protocols
set(_items "")
curl_add_if("HTTP"          NOT CURL_DISABLE_HTTP)
curl_add_if("HTTPS"         NOT CURL_DISABLE_HTTP AND _ssl_enabled)
curl_add_if("FTP"           NOT CURL_DISABLE_FTP)
curl_add_if("FTPS"          NOT CURL_DISABLE_FTP AND _ssl_enabled)
curl_add_if("FILE"          NOT CURL_DISABLE_FILE)
curl_add_if("TELNET"        NOT CURL_DISABLE_TELNET)
curl_add_if("LDAP"          NOT CURL_DISABLE_LDAP)
# CURL_DISABLE_LDAP implies CURL_DISABLE_LDAPS
curl_add_if("LDAPS"         NOT CURL_DISABLE_LDAPS AND
                            ((USE_OPENLDAP AND _ssl_enabled) OR
                            (NOT USE_OPENLDAP AND HAVE_LDAP_SSL)))
curl_add_if("DICT"          NOT CURL_DISABLE_DICT)
curl_add_if("TFTP"          NOT CURL_DISABLE_TFTP)
curl_add_if("GOPHER"        NOT CURL_DISABLE_GOPHER)
curl_add_if("GOPHERS"       NOT CURL_DISABLE_GOPHER AND _ssl_enabled)
curl_add_if("POP3"          NOT CURL_DISABLE_POP3)
curl_add_if("POP3S"         NOT CURL_DISABLE_POP3 AND _ssl_enabled)
curl_add_if("IMAP"          NOT CURL_DISABLE_IMAP)
curl_add_if("IMAPS"         NOT CURL_DISABLE_IMAP AND _ssl_enabled)
curl_add_if("SMB"           NOT CURL_DISABLE_SMB AND
                            _use_curl_ntlm_core AND (SIZEOF_CURL_OFF_T GREATER 4))
curl_add_if("SMBS"          NOT CURL_DISABLE_SMB AND _ssl_enabled AND
                            _use_curl_ntlm_core AND (SIZEOF_CURL_OFF_T GREATER 4))
curl_add_if("SMTP"          NOT CURL_DISABLE_SMTP)
curl_add_if("SMTPS"         NOT CURL_DISABLE_SMTP AND _ssl_enabled)
curl_add_if("SCP"           USE_LIBSSH2 OR USE_LIBSSH OR USE_WOLFSSH)
curl_add_if("SFTP"          USE_LIBSSH2 OR USE_LIBSSH OR USE_WOLFSSH)
curl_add_if("IPFS"          NOT CURL_DISABLE_IPFS)
curl_add_if("IPNS"          NOT CURL_DISABLE_IPFS)
curl_add_if("RTSP"          NOT CURL_DISABLE_RTSP)
curl_add_if("RTMP"          USE_LIBRTMP)
curl_add_if("MQTT"          NOT CURL_DISABLE_MQTT)
curl_add_if("WS"            NOT CURL_DISABLE_WEBSOCKETS)
curl_add_if("WSS"           NOT CURL_DISABLE_WEBSOCKETS AND _ssl_enabled)
if(_items)
  list(SORT _items)
endif()
set(CURL_SUPPORTED_PROTOCOLS_LIST "${_items}")
string(REPLACE ";" " " SUPPORT_PROTOCOLS "${_items}")
string(TOLOWER "${SUPPORT_PROTOCOLS}" _support_protocols_lower)
message(STATUS "Protocols: ${_support_protocols_lower}")

# Clear list and try to detect available features
set(_items "")
curl_add_if("SSL"           _ssl_enabled)
curl_add_if("IPv6"          USE_IPV6)
curl_add_if("UnixSockets"   USE_UNIX_SOCKETS)
curl_add_if("libz"          HAVE_LIBZ)
curl_add_if("brotli"        HAVE_BROTLI)
curl_add_if("gsasl"         USE_GSASL)
curl_add_if("zstd"          HAVE_ZSTD)
curl_add_if("AsynchDNS"     USE_ARES OR USE_THREADS_POSIX OR USE_THREADS_WIN32)
curl_add_if("asyn-rr"       USE_ARES AND ENABLE_THREADED_RESOLVER)
curl_add_if("IDN"           (HAVE_LIBIDN2 AND HAVE_IDN2_H) OR
                            USE_WIN32_IDN OR
                            USE_APPLE_IDN)
curl_add_if("Largefile"     (SIZEOF_CURL_OFF_T GREATER 4) AND
                            ((SIZEOF_OFF_T GREATER 4) OR USE_WIN32_LARGE_FILES))
curl_add_if("SSPI"          USE_WINDOWS_SSPI)
curl_add_if("GSS-API"       HAVE_GSSAPI)
curl_add_if("alt-svc"       NOT CURL_DISABLE_ALTSVC)
curl_add_if("HSTS"          NOT CURL_DISABLE_HSTS)
curl_add_if("SPNEGO"        NOT CURL_DISABLE_NEGOTIATE_AUTH AND
                            (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
curl_add_if("Kerberos"      NOT CURL_DISABLE_KERBEROS_AUTH AND
                            (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
curl_add_if("NTLM"          NOT (CURL_DISABLE_NTLM) AND
                            (_use_curl_ntlm_core OR USE_WINDOWS_SSPI))
curl_add_if("TLS-SRP"       USE_TLS_SRP)
curl_add_if("HTTP2"         USE_NGHTTP2)
curl_add_if("HTTP3"         USE_NGTCP2 OR USE_QUICHE OR USE_MSH3 OR USE_OPENSSL_QUIC)
curl_add_if("MultiSSL"      CURL_WITH_MULTI_SSL)
curl_add_if("HTTPS-proxy"   _ssl_enabled AND (USE_OPENSSL OR USE_GNUTLS
                            OR USE_SCHANNEL OR USE_RUSTLS OR USE_BEARSSL OR
                            USE_MBEDTLS OR USE_SECTRANSP OR
                            (USE_WOLFSSL AND HAVE_WOLFSSL_BIO)))
curl_add_if("Unicode"       ENABLE_UNICODE)
curl_add_if("threadsafe"    HAVE_ATOMIC OR
                            (USE_THREADS_POSIX AND HAVE_PTHREAD_H) OR
                            (WIN32 AND HAVE_WIN32_WINNT GREATER_EQUAL 0x0600))
curl_add_if("Debug"         ENABLE_DEBUG)
curl_add_if("TrackMemory"   ENABLE_CURLDEBUG)
curl_add_if("ECH"           _ssl_enabled AND HAVE_ECH)
curl_add_if("HTTPSRR"       _ssl_enabled AND USE_HTTPSRR)
curl_add_if("PSL"           USE_LIBPSL)
curl_add_if("CAcert"        CURL_CA_EMBED_SET)
curl_add_if("SSLS-EXPORT"   _ssl_enabled AND USE_SSLS_EXPORT)
if(_items)
  if(NOT CMAKE_VERSION VERSION_LESS 3.13)
    list(SORT _items CASE INSENSITIVE)
  else()
    list(SORT _items)
  endif()
endif()
set(CURL_SUPPORTED_FEATURES_LIST "${_items}")
string(REPLACE ";" " " SUPPORT_FEATURES "${_items}")
message(STATUS "Features: ${SUPPORT_FEATURES}")

# Clear list and collect SSL backends
set(_items "")
curl_add_if("Schannel"         _ssl_enabled AND USE_SCHANNEL)
curl_add_if("${_openssl}"      _ssl_enabled AND USE_OPENSSL AND OPENSSL_VERSION VERSION_LESS 3.0.0)
curl_add_if("${_openssl} v3+"  _ssl_enabled AND USE_OPENSSL AND NOT OPENSSL_VERSION VERSION_LESS 3.0.0)
curl_add_if("Secure Transport" _ssl_enabled AND USE_SECTRANSP)
curl_add_if("mbedTLS"          _ssl_enabled AND USE_MBEDTLS)
curl_add_if("BearSSL"          _ssl_enabled AND USE_BEARSSL)
curl_add_if("wolfSSL"          _ssl_enabled AND USE_WOLFSSL)
curl_add_if("GnuTLS"           _ssl_enabled AND USE_GNUTLS)
curl_add_if("rustls"           _ssl_enabled AND USE_RUSTLS)

if(_items)
  if(NOT CMAKE_VERSION VERSION_LESS 3.13)
    list(SORT _items CASE INSENSITIVE)
  else()
    list(SORT _items)
  endif()
endif()
string(REPLACE ";" " " SSL_BACKENDS "${_items}")
message(STATUS "Enabled SSL backends: ${SSL_BACKENDS}")
if(CURL_DEFAULT_SSL_BACKEND)
  message(STATUS "Default SSL backend: ${CURL_DEFAULT_SSL_BACKEND}")
endif()

if(NOT CURL_DISABLE_INSTALL)

  # curl-config needs the following options to be set.
  set(CC                      "${CMAKE_C_COMPILER}")
  # TODO: probably put a -D... options here?
  set(CONFIGURE_OPTIONS       "")
  set(CURLVERSION             "${_curl_version}")
  set(VERSIONNUM              "${_curl_version_num}")
  set(prefix                  "${CMAKE_INSTALL_PREFIX}")
  set(exec_prefix             "\${prefix}")
  if(IS_ABSOLUTE ${CMAKE_INSTALL_INCLUDEDIR})
    set(includedir            "${CMAKE_INSTALL_INCLUDEDIR}")
  else()
    set(includedir            "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
  endif()
  if(IS_ABSOLUTE ${CMAKE_INSTALL_LIBDIR})
    set(libdir                "${CMAKE_INSTALL_LIBDIR}")
  else()
    set(libdir                "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
  endif()
  # "a" (Linux) or "lib" (Windows)
  string(REPLACE "." "" libext "${CMAKE_STATIC_LIBRARY_SUFFIX}")

  set(_ldflags "")
  set(LIBCURL_PC_LIBS_PRIVATE "")

  # Filter CMAKE_SHARED_LINKER_FLAGS for libs and libpaths
  string(STRIP "${CMAKE_SHARED_LINKER_FLAGS}" _custom_ldflags)
  string(REGEX REPLACE " +-([^ \\t;]*)" ";-\\1" _custom_ldflags "${_custom_ldflags}")

  set(_custom_libs "")
  set(_custom_libdirs "")
  foreach(_flag IN LISTS _custom_ldflags)
    if(_flag MATCHES "^-l")
      string(REGEX REPLACE "^-l" "" _flag "${_flag}")
      list(APPEND _custom_libs "${_flag}")
    elseif(_flag MATCHES "^-framework|^-F")
      list(APPEND _custom_libs "${_flag}")
    elseif(_flag MATCHES "^-L")
      string(REGEX REPLACE "^-L" "" _flag "${_flag}")
      list(APPEND _custom_libdirs "${_flag}")
    elseif(_flag MATCHES "^--library-path=")
      string(REGEX REPLACE "^--library-path=" "" _flag "${_flag}")
      list(APPEND _custom_libdirs "${_flag}")
    endif()
  endforeach()

  # Avoid getting unnecessary -L options for known system directories.
  set(_sys_libdirs "")
  foreach(_libdir IN LISTS CMAKE_SYSTEM_PREFIX_PATH)
    if(_libdir MATCHES "/$")
      set(_libdir "${_libdir}lib")
    else()
      set(_libdir "${_libdir}/lib")
    endif()
    if(IS_DIRECTORY "${_libdir}")
      list(APPEND _sys_libdirs "${_libdir}")
    endif()
    if(DEFINED CMAKE_LIBRARY_ARCHITECTURE)
      set(_libdir "${_libdir}/${CMAKE_LIBRARY_ARCHITECTURE}")
      if(IS_DIRECTORY "${_libdir}")
        list(APPEND _sys_libdirs "${_libdir}")
      endif()
    endif()
  endforeach()

  foreach(_libdir IN LISTS _custom_libdirs CURL_LIBDIRS)
    list(FIND _sys_libdirs "${_libdir}" _libdir_index)
    if(_libdir_index LESS 0)
      list(APPEND _ldflags "-L${_libdir}")
    endif()
  endforeach()

  set(_implicit_libs "")
  if(NOT MINGW AND NOT UNIX)
    set(_implicit_libs ${CMAKE_C_IMPLICIT_LINK_LIBRARIES})
  endif()

  foreach(_lib IN LISTS _implicit_libs _custom_libs CURL_LIBS)
    if(TARGET "${_lib}")
      set(_libname "${_lib}")
      get_target_property(_imported "${_libname}" IMPORTED)
      if(NOT _imported)
        # Reading the LOCATION property on non-imported target will error out.
        # Assume the user will not need this information in the .pc file.
        continue()
      endif()
      get_target_property(_lib "${_libname}" LOCATION)
      if(NOT _lib)
        message(WARNING "Bad lib in library list: ${_libname}")
        continue()
      endif()
    endif()
    if(_lib MATCHES "^-")  # '-framework <name>'
      list(APPEND _ldflags "${_lib}")
    elseif(_lib MATCHES "/")
      # This gets a bit more complex, because we want to specify the
      # directory separately, and only once per directory
      get_filename_component(_libdir ${_lib} DIRECTORY)
      get_filename_component(_libname ${_lib} NAME_WE)
      if(_libname MATCHES "^lib")
        list(FIND _sys_libdirs "${_libdir}" _libdir_index)
        if(_libdir_index LESS 0)
          list(APPEND _ldflags "-L${_libdir}")
        endif()
        string(REGEX REPLACE "^lib" "" _libname "${_libname}")
        list(APPEND LIBCURL_PC_LIBS_PRIVATE "-l${_libname}")
      else()
        list(APPEND LIBCURL_PC_LIBS_PRIVATE "${_lib}")
      endif()
    else()
      list(APPEND LIBCURL_PC_LIBS_PRIVATE "-l${_lib}")
    endif()
  endforeach()

  if(LIBCURL_PC_REQUIRES_PRIVATE)
    string(REPLACE ";" "," LIBCURL_PC_REQUIRES_PRIVATE "${LIBCURL_PC_REQUIRES_PRIVATE}")
  endif()
  if(LIBCURL_PC_LIBS_PRIVATE)
    string(REPLACE ";" " " LIBCURL_PC_LIBS_PRIVATE "${LIBCURL_PC_LIBS_PRIVATE}")
  endif()
  if(_ldflags)
    list(REMOVE_DUPLICATES _ldflags)
    string(REPLACE ";" " " _ldflags "${_ldflags}")
    set(LIBCURL_PC_LDFLAGS_PRIVATE "${_ldflags}")
    string(STRIP "${LIBCURL_PC_LDFLAGS_PRIVATE}" LIBCURL_PC_LDFLAGS_PRIVATE)
  else()
    set(LIBCURL_PC_LDFLAGS_PRIVATE "")
  endif()
  set(LIBCURL_PC_CFLAGS_PRIVATE "-DCURL_STATICLIB")

  # Merge pkg-config private fields into public ones when static-only
  if(BUILD_SHARED_LIBS)
    set(ENABLE_SHARED       "yes")
    set(LIBCURL_PC_REQUIRES "")
    set(LIBCURL_PC_LIBS     "")
    set(LIBCURL_PC_CFLAGS   "")
  else()
    set(ENABLE_SHARED       "no")
    set(LIBCURL_PC_REQUIRES "${LIBCURL_PC_REQUIRES_PRIVATE}")
    set(LIBCURL_PC_LIBS     "${LIBCURL_PC_LIBS_PRIVATE}")
    set(LIBCURL_PC_CFLAGS   "${LIBCURL_PC_CFLAGS_PRIVATE}")
  endif()
  if(BUILD_STATIC_LIBS)
    set(ENABLE_STATIC       "yes")
  else()
    set(ENABLE_STATIC       "no")
  endif()

  # Generate a "curl-config" matching this config.
  # Consumed variables:
  #   CC
  #   CONFIGURE_OPTIONS
  #   CURLVERSION
  #   CURL_CA_BUNDLE
  #   ENABLE_SHARED
  #   ENABLE_STATIC
  #   exec_prefix
  #   includedir
  #   LIBCURL_PC_CFLAGS
  #   LIBCURL_PC_LDFLAGS_PRIVATE
  #   LIBCURL_PC_LIBS_PRIVATE
  #   libdir
  #   libext
  #   prefix
  #   SSL_BACKENDS
  #   SUPPORT_FEATURES
  #   SUPPORT_PROTOCOLS
  #   VERSIONNUM
  configure_file(
    "${PROJECT_SOURCE_DIR}/curl-config.in"
    "${PROJECT_BINARY_DIR}/curl-config" @ONLY)
  install(FILES "${PROJECT_BINARY_DIR}/curl-config"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS
      OWNER_READ OWNER_WRITE OWNER_EXECUTE
      GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)

  # Generate a pkg-config file matching this config.
  # Consumed variables:
  #   CURLVERSION
  #   exec_prefix
  #   includedir
  #   LIBCURL_PC_CFLAGS
  #   LIBCURL_PC_CFLAGS_PRIVATE
  #   LIBCURL_PC_LDFLAGS_PRIVATE
  #   LIBCURL_PC_LIBS
  #   LIBCURL_PC_LIBS_PRIVATE
  #   LIBCURL_PC_REQUIRES
  #   LIBCURL_PC_REQUIRES_PRIVATE
  #   libdir
  #   prefix
  #   SUPPORT_FEATURES
  #   SUPPORT_PROTOCOLS
  # Documentation:
  #   https://people.freedesktop.org/~dbn/pkg-config-guide.html
  #   https://manpages.debian.org/unstable/pkgconf/pkg-config.1.en.html
  #   https://manpages.debian.org/unstable/pkg-config/pkg-config.1.en.html
  #   https://www.msys2.org/docs/pkgconfig/
  configure_file(
    "${PROJECT_SOURCE_DIR}/libcurl.pc.in"
    "${PROJECT_BINARY_DIR}/libcurl.pc" @ONLY)
  install(FILES "${PROJECT_BINARY_DIR}/libcurl.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

  # Install headers
  install(DIRECTORY "${PROJECT_SOURCE_DIR}/include/curl"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")

  include(CMakePackageConfigHelpers)
  write_basic_package_version_file(
    "${_version_config}"
    VERSION ${_curl_version}
    COMPATIBILITY SameMajorVersion)
  file(READ "${_version_config}" _generated_version_config)
  file(WRITE "${_version_config}" "
    if(NOT PACKAGE_FIND_VERSION_RANGE AND PACKAGE_FIND_VERSION_MAJOR STREQUAL \"7\")
      # Version 8 satisfies version 7... requirements
      set(PACKAGE_FIND_VERSION_MAJOR 8)
      set(PACKAGE_FIND_VERSION_COUNT 1)
    endif()
    ${_generated_version_config}")

  # Consumed custom variables:
  #   CURLVERSION
  #   LIB_SELECTED
  #   TARGETS_EXPORT_NAME
  #   USE_OPENSSL OPENSSL_VERSION_MAJOR
  #   HAVE_LIBZ ZLIB_VERSION_MAJOR
  #   CURL_SUPPORTED_FEATURES_LIST
  #   CURL_SUPPORTED_PROTOCOLS_LIST
  configure_package_config_file("CMake/curl-config.cmake.in"
    "${_project_config}"
    INSTALL_DESTINATION ${_install_cmake_dir}
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR)

  if(CURL_ENABLE_EXPORT_TARGET)
    install(EXPORT "${TARGETS_EXPORT_NAME}"
      NAMESPACE "${PROJECT_NAME}::"
      DESTINATION ${_install_cmake_dir})
  endif()

  install(FILES ${_version_config} ${_project_config}
    DESTINATION ${_install_cmake_dir})

  if(NOT TARGET curl_uninstall)
    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/CMake/cmake_uninstall.cmake.in"
      "${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake"
      @ONLY)

    add_custom_target(curl_uninstall
      COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake")
  endif()

  install(FILES "${PROJECT_SOURCE_DIR}/scripts/mk-ca-bundle.pl"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS
      OWNER_READ OWNER_WRITE OWNER_EXECUTE
      GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)

  # The `-DEV` part is important
  string(REGEX REPLACE "([0-9]+\.[0-9]+)\.([0-9]+.*)" "\\2" CPACK_PACKAGE_VERSION_PATCH "${_curl_version}")
  set(CPACK_GENERATOR "TGZ")
  include(CPack)
endif()

# Save build info for test runner to pick up and log
if(CMAKE_OSX_SYSROOT)
  set(_cmake_sysroot ${CMAKE_OSX_SYSROOT})
elseif(CMAKE_SYSROOT)
  set(_cmake_sysroot ${CMAKE_SYSROOT})
endif()
set(_buildinfo "\
buildinfo.configure.tool: cmake
buildinfo.configure.command: ${CMAKE_COMMAND}
buildinfo.configure.version: ${CMAKE_VERSION}
buildinfo.configure.args:${_cmake_args}
buildinfo.configure.generator: ${CMAKE_GENERATOR}
buildinfo.configure.make: ${CMAKE_MAKE_PROGRAM}
buildinfo.host.cpu: ${CMAKE_HOST_SYSTEM_PROCESSOR}
buildinfo.host.os: ${CMAKE_HOST_SYSTEM_NAME}
buildinfo.target.cpu: ${CMAKE_SYSTEM_PROCESSOR}
buildinfo.target.os: ${CMAKE_SYSTEM_NAME}
buildinfo.target.flags:${_target_flags}
buildinfo.compiler: ${CMAKE_C_COMPILER_ID}
buildinfo.compiler.version: ${CMAKE_C_COMPILER_VERSION}
buildinfo.sysroot: ${_cmake_sysroot}
")
file(WRITE "${PROJECT_BINARY_DIR}/buildinfo.txt" "# This is a generated file.  Do not edit.\n${_buildinfo}")
if(NOT "$ENV{CURL_BUILDINFO}$ENV{CURL_CI}$ENV{CI}" STREQUAL "")
  message(STATUS "\n${_buildinfo}")
endif()
