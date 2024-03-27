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
# dependencies using `check_symbol_exists`.  Those checks do not work
# in the case that both CURL and its dependency are included as
# sub-projects in a larger build using `FetchContent`.  To support
# that case, additional variables may be defined by the parent
# project, ideally in the "extra" find package redirect file:
# https://cmake.org/cmake/help/latest/module/FetchContent.html#integrating-with-find-package
#
# The following variables are available:
#   HAVE_SSL_SET0_WBIO: `SSL_set0_wbio` present in OpenSSL/wolfSSL
#   HAVE_OPENSSL_SRP: `SSL_CTX_set_srp_username` present in OpenSSL/wolfSSL
#   HAVE_GNUTLS_SRP: `gnutls_srp_verifier` present in GnuTLS
#   HAVE_SSL_CTX_SET_QUIC_METHOD: `SSL_CTX_set_quic_method` present in OpenSSL/wolfSSL
#   HAVE_QUICHE_CONN_SET_QLOG_FD: `quiche_conn_set_qlog_fd` present in QUICHE
#
# For each of the above variables, if the variable is DEFINED (either
# to ON or OFF), the symbol detection will be skipped.  If the
# variable is NOT DEFINED, the symbol detection will be performed.

cmake_minimum_required(VERSION 3.7...3.16 FATAL_ERROR)
message(STATUS "Using CMake version ${CMAKE_VERSION}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")
include(Utilities)
include(Macros)
include(CMakeDependentOption)
include(CheckCCompilerFlag)

project(CURL C)

file(STRINGS ${CURL_SOURCE_DIR}/include/curl/curlver.h CURL_VERSION_H_CONTENTS REGEX "#define LIBCURL_VERSION( |_NUM )")
string(REGEX MATCH "#define LIBCURL_VERSION \"[^\"]*"
  CURL_VERSION ${CURL_VERSION_H_CONTENTS})
string(REGEX REPLACE "[^\"]+\"" "" CURL_VERSION ${CURL_VERSION})
string(REGEX MATCH "#define LIBCURL_VERSION_NUM 0x[0-9a-fA-F]+"
  CURL_VERSION_NUM ${CURL_VERSION_H_CONTENTS})
string(REGEX REPLACE "[^0]+0x" "" CURL_VERSION_NUM ${CURL_VERSION_NUM})


# Setup package meta-data
# SET(PACKAGE "curl")
message(STATUS "curl version=[${CURL_VERSION}]")
# SET(PACKAGE_TARNAME "curl")
# SET(PACKAGE_NAME "curl")
# SET(PACKAGE_VERSION "-")
# SET(PACKAGE_STRING "curl-")
# SET(PACKAGE_BUGREPORT "a suitable curl mailing list => https://curl.se/mail/")
set(OPERATING_SYSTEM "${CMAKE_SYSTEM_NAME}")
if(CMAKE_C_COMPILER_TARGET)
  set(OS "\"${CMAKE_C_COMPILER_TARGET}\"")
else()
  set(OS "\"${CMAKE_SYSTEM_NAME}\"")
endif()

include_directories(${CURL_SOURCE_DIR}/include)

set(CMAKE_UNITY_BUILD_BATCH_SIZE 0)

option(CURL_WERROR "Turn compiler warnings into errors" OFF)
option(PICKY_COMPILER "Enable picky compiler options" ON)
option(BUILD_CURL_EXE "Set to ON to build curl executable." ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" OFF)
option(BUILD_STATIC_CURL "Build curl executable with static libcurl" OFF)
option(ENABLE_ARES "Set to ON to enable c-ares support" OFF)
option(CURL_DISABLE_INSTALL "Set to ON to disable installation targets" OFF)

if(WIN32)
  option(CURL_STATIC_CRT "Set to ON to build libcurl with static CRT on Windows (/MT)." OFF)
  option(ENABLE_UNICODE "Set to ON to use the Unicode version of the Windows API functions" OFF)
  set(CURL_TARGET_WINDOWS_VERSION "" CACHE STRING "Minimum target Windows version as hex string")
  if(CURL_TARGET_WINDOWS_VERSION)
    add_definitions(-D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION})
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION})
    set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION}")
  endif()
  if(ENABLE_UNICODE)
    add_definitions(-DUNICODE -D_UNICODE)
    if(MINGW)
      add_compile_options(-municode)
    endif()
  endif()
endif()
option(CURL_LTO "Turn on compiler Link Time Optimizations" OFF)

cmake_dependent_option(ENABLE_THREADED_RESOLVER "Set to ON to enable threaded DNS lookup"
        ON "NOT ENABLE_ARES"
        OFF)

option(ENABLE_DEBUG "Set to ON to enable curl debug features" OFF)
option(ENABLE_CURLDEBUG "Set to ON to build with TrackMemory feature enabled" OFF)

include(PickyWarnings)

if(ENABLE_DEBUG)
  # DEBUGBUILD will be defined only for Debug builds
  set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
  set(ENABLE_CURLDEBUG ON)
endif()

if(ENABLE_CURLDEBUG)
  set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS CURLDEBUG)
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

# lib flavour selected for curl tool
if(BUILD_STATIC_CURL)
  set(LIB_SELECTED_FOR_EXE ${LIB_STATIC})
else()
  set(LIB_SELECTED_FOR_EXE ${LIB_SHARED})
endif()

# lib flavour selected for example and test programs.
if(BUILD_SHARED_LIBS)
  set(LIB_SELECTED ${LIB_SHARED})
else()
  set(LIB_SELECTED ${LIB_STATIC})
endif()

# initialize CURL_LIBS
set(CURL_LIBS "")

if(ENABLE_ARES)
  set(USE_ARES 1)
  find_package(CARES REQUIRED)
  list(APPEND CURL_LIBS ${CARES_LIBRARY})
endif()

include(CurlSymbolHiding)

option(CURL_ENABLE_EXPORT_TARGET "to enable cmake export target" ON)
mark_as_advanced(CURL_ENABLE_EXPORT_TARGET)

option(CURL_DISABLE_ALTSVC "disables alt-svc support" OFF)
mark_as_advanced(CURL_DISABLE_ALTSVC)
option(CURL_DISABLE_SRP "disables TLS-SRP support" OFF)
mark_as_advanced(CURL_DISABLE_SRP)
option(CURL_DISABLE_COOKIES "disables cookies support" OFF)
mark_as_advanced(CURL_DISABLE_COOKIES)
option(CURL_DISABLE_BASIC_AUTH "disables Basic authentication" OFF)
mark_as_advanced(CURL_DISABLE_BASIC_AUTH)
option(CURL_DISABLE_BEARER_AUTH "disables Bearer authentication" OFF)
mark_as_advanced(CURL_DISABLE_BEARER_AUTH)
option(CURL_DISABLE_DIGEST_AUTH "disables Digest authentication" OFF)
mark_as_advanced(CURL_DISABLE_DIGEST_AUTH)
option(CURL_DISABLE_KERBEROS_AUTH "disables Kerberos authentication" OFF)
mark_as_advanced(CURL_DISABLE_KERBEROS_AUTH)
option(CURL_DISABLE_NEGOTIATE_AUTH "disables negotiate authentication" OFF)
mark_as_advanced(CURL_DISABLE_NEGOTIATE_AUTH)
option(CURL_DISABLE_AWS "disables AWS-SIG4" OFF)
mark_as_advanced(CURL_DISABLE_AWS)
option(CURL_DISABLE_DICT "disables DICT" OFF)
mark_as_advanced(CURL_DISABLE_DICT)
option(CURL_DISABLE_DOH "disables DNS-over-HTTPS" OFF)
mark_as_advanced(CURL_DISABLE_DOH)
option(CURL_DISABLE_FILE "disables FILE" OFF)
mark_as_advanced(CURL_DISABLE_FILE)
cmake_dependent_option(CURL_DISABLE_FORM_API "disables form api" OFF
                       "NOT CURL_DISABLE_MIME" ON)
mark_as_advanced(CURL_DISABLE_FORM_API)
option(CURL_DISABLE_FTP "disables FTP" OFF)
mark_as_advanced(CURL_DISABLE_FTP)
option(CURL_DISABLE_GETOPTIONS "disables curl_easy_options API for existing options to curl_easy_setopt" OFF)
mark_as_advanced(CURL_DISABLE_GETOPTIONS)
option(CURL_DISABLE_GOPHER "disables Gopher" OFF)
mark_as_advanced(CURL_DISABLE_GOPHER)
option(CURL_DISABLE_HEADERS_API "disables headers-api support" OFF)
mark_as_advanced(CURL_DISABLE_HEADERS_API)
option(CURL_DISABLE_HSTS "disables HSTS support" OFF)
mark_as_advanced(CURL_DISABLE_HSTS)
option(CURL_DISABLE_HTTP "disables HTTP" OFF)
mark_as_advanced(CURL_DISABLE_HTTP)
option(CURL_DISABLE_HTTP_AUTH "disables all HTTP authentication methods" OFF)
mark_as_advanced(CURL_DISABLE_HTTP_AUTH)
option(CURL_DISABLE_IMAP "disables IMAP" OFF)
mark_as_advanced(CURL_DISABLE_IMAP)
option(CURL_DISABLE_LDAP "disables LDAP" OFF)
mark_as_advanced(CURL_DISABLE_LDAP)
option(CURL_DISABLE_LDAPS "disables LDAPS" OFF)
mark_as_advanced(CURL_DISABLE_LDAPS)
option(CURL_DISABLE_LIBCURL_OPTION "disables --libcurl option from the curl tool" OFF)
mark_as_advanced(CURL_DISABLE_LIBCURL_OPTION)
option(CURL_DISABLE_MIME "disables MIME support" OFF)
mark_as_advanced(CURL_DISABLE_MIME)
option(CURL_DISABLE_MQTT "disables MQTT" OFF)
mark_as_advanced(CURL_DISABLE_BINDLOCAL)
option(CURL_DISABLE_BINDLOCAL "disables local binding support" OFF)
mark_as_advanced(CURL_DISABLE_MQTT)
option(CURL_DISABLE_NETRC "disables netrc parser" OFF)
mark_as_advanced(CURL_DISABLE_NETRC)
option(CURL_DISABLE_NTLM "disables NTLM support" OFF)
mark_as_advanced(CURL_DISABLE_NTLM)
option(CURL_DISABLE_PARSEDATE "disables date parsing" OFF)
mark_as_advanced(CURL_DISABLE_PARSEDATE)
option(CURL_DISABLE_POP3 "disables POP3" OFF)
mark_as_advanced(CURL_DISABLE_POP3)
option(CURL_DISABLE_PROGRESS_METER "disables built-in progress meter" OFF)
mark_as_advanced(CURL_DISABLE_PROGRESS_METER)
option(CURL_DISABLE_PROXY "disables proxy support" OFF)
mark_as_advanced(CURL_DISABLE_PROXY)
option(CURL_DISABLE_RTSP "disables RTSP" OFF)
mark_as_advanced(CURL_DISABLE_RTSP)
option(CURL_DISABLE_SHUFFLE_DNS "disables shuffle DNS feature" OFF)
mark_as_advanced(CURL_DISABLE_SHUFFLE_DNS)
option(CURL_DISABLE_SMB "disables SMB" OFF)
mark_as_advanced(CURL_DISABLE_SMB)
option(CURL_DISABLE_SMTP "disables SMTP" OFF)
mark_as_advanced(CURL_DISABLE_SMTP)
option(CURL_DISABLE_SOCKETPAIR "disables use of socketpair for curl_multi_poll" OFF)
mark_as_advanced(CURL_DISABLE_SOCKETPAIR)
option(CURL_DISABLE_TELNET "disables Telnet" OFF)
mark_as_advanced(CURL_DISABLE_TELNET)
option(CURL_DISABLE_TFTP "disables TFTP" OFF)
mark_as_advanced(CURL_DISABLE_TFTP)
option(CURL_DISABLE_VERBOSE_STRINGS "disables verbose strings" OFF)
mark_as_advanced(CURL_DISABLE_VERBOSE_STRINGS)

# Corresponds to HTTP_ONLY in lib/curl_setup.h
option(HTTP_ONLY "disables all protocols except HTTP (This overrides all CURL_DISABLE_* options)" OFF)
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
  set(CURL_DISABLE_RTSP ON)
  set(CURL_DISABLE_SMB ON)
  set(CURL_DISABLE_SMTP ON)
  set(CURL_DISABLE_TELNET ON)
  set(CURL_DISABLE_TFTP ON)
endif()

option(ENABLE_IPV6 "Define if you want to enable IPv6 support" ON)
mark_as_advanced(ENABLE_IPV6)
if(ENABLE_IPV6 AND NOT WIN32)
  include(CheckStructHasMember)
  check_struct_has_member("struct sockaddr_in6" sin6_addr "netinet/in.h"
                          HAVE_SOCKADDR_IN6_SIN6_ADDR)
  check_struct_has_member("struct sockaddr_in6" sin6_scope_id "netinet/in.h"
                          HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(NOT HAVE_SOCKADDR_IN6_SIN6_ADDR)
    message(WARNING "struct sockaddr_in6 not available, disabling IPv6 support")
    # Force the feature off as this name is used as guard macro...
    set(ENABLE_IPV6 OFF
        CACHE BOOL "Define if you want to enable IPv6 support" FORCE)
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT ENABLE_ARES)
    set(use_core_foundation_and_core_services ON)

    find_library(SYSTEMCONFIGURATION_FRAMEWORK "SystemConfiguration")
    if(NOT SYSTEMCONFIGURATION_FRAMEWORK)
      message(FATAL_ERROR "SystemConfiguration framework not found")
    endif()

    list(APPEND CURL_LIBS "-framework SystemConfiguration")
  endif()
endif()

find_package(Perl)

option(BUILD_LIBCURL_DOCS "to build libcurl man pages" ON)
option(BUILD_MISC_DOCS "to build misc man pages (e.g. curl-config and mk-ca-bundle)" ON)
option(ENABLE_CURL_MANUAL "to build the man page for curl and enable its -M/--manual option" ON)

if(ENABLE_CURL_MANUAL OR BUILD_LIBCURL_DOCS)
  if(PERL_FOUND)
    set(HAVE_MANUAL_TOOLS ON)
  endif()
  if(NOT HAVE_MANUAL_TOOLS)
    message(WARNING "Perl not found. Will not build manuals.")
  endif()
endif()

if(CURL_STATIC_CRT)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
endif()

# Disable warnings on Borland to avoid changing 3rd party code.
if(BORLAND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w-")
endif()

# If we are on AIX, do the _ALL_SOURCE magic
if(${CMAKE_SYSTEM_NAME} MATCHES AIX)
  set(_ALL_SOURCE 1)
endif()

# If we are on Haiku, make sure that the network library is brought in.
if(${CMAKE_SYSTEM_NAME} MATCHES Haiku)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lnetwork")
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

# On windows preload settings
if(WIN32)
  include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/Platforms/WindowsCache.cmake)
endif()

if(ENABLE_THREADED_RESOLVER)
  if(WIN32)
    set(USE_THREADS_WIN32 ON)
  else()
    find_package(Threads REQUIRED)
    set(USE_THREADS_POSIX ${CMAKE_USE_PTHREADS_INIT})
    set(HAVE_PTHREAD_H ${CMAKE_USE_PTHREADS_INIT})
    set(CURL_LIBS ${CURL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
  endif()
endif()

# Check for all needed libraries
check_library_exists("socket" "connect" "" HAVE_LIBSOCKET)
if(HAVE_LIBSOCKET)
  set(CURL_LIBS "socket;${CURL_LIBS}")
endif()

check_function_exists(gethostname HAVE_GETHOSTNAME)

if(WIN32)
  list(APPEND CURL_LIBS "ws2_32" "bcrypt")
  if(USE_LIBRTMP)
    list(APPEND CURL_LIBS "winmm")
  endif()
endif()

# check SSL libraries
option(CURL_ENABLE_SSL "Enable SSL support" ON)

if(CURL_DEFAULT_SSL_BACKEND)
  set(valid_default_ssl_backend FALSE)
endif()

if(APPLE)
  cmake_dependent_option(CURL_USE_SECTRANSP "Enable Apple OS native SSL/TLS" OFF CURL_ENABLE_SSL OFF)
endif()
if(WIN32)
  cmake_dependent_option(CURL_USE_SCHANNEL "Enable Windows native SSL/TLS" OFF CURL_ENABLE_SSL OFF)
  option(CURL_WINDOWS_SSPI "Enable SSPI on Windows" ${CURL_USE_SCHANNEL})
endif()
cmake_dependent_option(CURL_USE_MBEDTLS "Enable mbedTLS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_BEARSSL "Enable BearSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_WOLFSSL "Enable wolfSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_GNUTLS "Enable GnuTLS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)

set(openssl_default ON)
if(WIN32 OR CURL_USE_SECTRANSP OR CURL_USE_SCHANNEL OR CURL_USE_MBEDTLS OR CURL_USE_WOLFSSL)
  set(openssl_default OFF)
endif()
cmake_dependent_option(CURL_USE_OPENSSL "Enable OpenSSL for SSL/TLS" ${openssl_default} CURL_ENABLE_SSL OFF)
option(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG "Disable automatic loading of OpenSSL configuration" OFF)

count_true(enabled_ssl_options_count
  CURL_USE_SCHANNEL
  CURL_USE_SECTRANSP
  CURL_USE_OPENSSL
  CURL_USE_MBEDTLS
  CURL_USE_BEARSSL
  CURL_USE_WOLFSSL
)
if(enabled_ssl_options_count GREATER "1")
  set(CURL_WITH_MULTI_SSL ON)
endif()

if(CURL_USE_SCHANNEL)
  set(SSL_ENABLED ON)
  set(USE_SCHANNEL ON) # Windows native SSL/TLS support
  set(USE_WINDOWS_SSPI ON) # CURL_USE_SCHANNEL implies CURL_WINDOWS_SSPI

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "schannel")
    set(valid_default_ssl_backend TRUE)
  endif()
endif()
if(CURL_WINDOWS_SSPI)
  set(USE_WINDOWS_SSPI ON)
endif()

if(CURL_USE_SECTRANSP)
  set(use_core_foundation_and_core_services ON)

  find_library(SECURITY_FRAMEWORK "Security")
  if(NOT SECURITY_FRAMEWORK)
     message(FATAL_ERROR "Security framework not found")
  endif()

  set(SSL_ENABLED ON)
  set(USE_SECTRANSP ON)
  list(APPEND CURL_LIBS "-framework Security")

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "secure-transport")
    set(valid_default_ssl_backend TRUE)
  endif()
endif()

if(use_core_foundation_and_core_services)
  find_library(COREFOUNDATION_FRAMEWORK "CoreFoundation")
  find_library(CORESERVICES_FRAMEWORK "CoreServices")

  if(NOT COREFOUNDATION_FRAMEWORK)
      message(FATAL_ERROR "CoreFoundation framework not found")
  endif()
  if(NOT CORESERVICES_FRAMEWORK)
      message(FATAL_ERROR "CoreServices framework not found")
  endif()

  list(APPEND CURL_LIBS "-framework CoreFoundation -framework CoreServices")
endif()

if(CURL_USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_OPENSSL ON)

  # Depend on OpenSSL via imported targets if supported by the running
  # version of CMake.  This allows our dependents to get our dependencies
  # transitively.
  if(NOT CMAKE_VERSION VERSION_LESS 3.4)
    list(APPEND CURL_LIBS OpenSSL::SSL OpenSSL::Crypto)
  else()
    list(APPEND CURL_LIBS ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
  endif()

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "openssl")
    set(valid_default_ssl_backend TRUE)
  endif()

  set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
  if(NOT DEFINED HAVE_BORINGSSL)
    check_symbol_exists(OPENSSL_IS_BORINGSSL "openssl/base.h" HAVE_BORINGSSL)
  endif()
  if(NOT DEFINED HAVE_AWSLC)
    check_symbol_exists(OPENSSL_IS_AWSLC "openssl/base.h" HAVE_AWSLC)
  endif()
endif()

if(CURL_USE_MBEDTLS)
  find_package(MbedTLS REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_MBEDTLS ON)
  list(APPEND CURL_LIBS ${MBEDTLS_LIBRARIES})
  include_directories(${MBEDTLS_INCLUDE_DIRS})

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "mbedtls")
    set(valid_default_ssl_backend TRUE)
  endif()
endif()

if(CURL_USE_BEARSSL)
  find_package(BearSSL REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_BEARSSL ON)
  list(APPEND CURL_LIBS ${BEARSSL_LIBRARY})
  include_directories(${BEARSSL_INCLUDE_DIRS})

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "bearssl")
    set(valid_default_ssl_backend TRUE)
  endif()
endif()

if(CURL_USE_WOLFSSL)
  find_package(WolfSSL REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_WOLFSSL ON)
  list(APPEND CURL_LIBS ${WolfSSL_LIBRARIES})
  include_directories(${WolfSSL_INCLUDE_DIRS})

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "wolfssl")
    set(valid_default_ssl_backend TRUE)
  endif()
endif()

if(CURL_USE_GNUTLS)
  find_package(GnuTLS REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_GNUTLS ON)
  list(APPEND CURL_LIBS ${GNUTLS_LIBRARIES} "nettle")
  include_directories(${GNUTLS_INCLUDE_DIRS})

  if(CURL_DEFAULT_SSL_BACKEND AND CURL_DEFAULT_SSL_BACKEND STREQUAL "gnutls")
    set(valid_default_ssl_backend TRUE)
  endif()

  if(NOT DEFINED HAVE_GNUTLS_SRP AND NOT CURL_DISABLE_SRP)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${GNUTLS_INCLUDE_DIRS})
    set(CMAKE_REQUIRED_LIBRARIES ${GNUTLS_LIBRARIES})
    check_symbol_exists(gnutls_srp_verifier "gnutls/gnutls.h" HAVE_GNUTLS_SRP)
    cmake_pop_check_state()
  endif()
endif()

if(CURL_DEFAULT_SSL_BACKEND AND NOT valid_default_ssl_backend)
  message(FATAL_ERROR "CURL_DEFAULT_SSL_BACKEND '${CURL_DEFAULT_SSL_BACKEND}' not enabled.")
endif()

# Keep ZLIB detection after TLS detection,
# and before calling openssl_check_symbol_exists().

set(HAVE_LIBZ OFF)
set(USE_ZLIB OFF)
optional_dependency(ZLIB)
if(ZLIB_FOUND)
  set(HAVE_LIBZ ON)
  set(USE_ZLIB ON)

  # Depend on ZLIB via imported targets if supported by the running
  # version of CMake.  This allows our dependents to get our dependencies
  # transitively.
  if(NOT CMAKE_VERSION VERSION_LESS 3.4)
    list(APPEND CURL_LIBS ZLIB::ZLIB)
  else()
    list(APPEND CURL_LIBS ${ZLIB_LIBRARIES})
    include_directories(${ZLIB_INCLUDE_DIRS})
  endif()
  list(APPEND CMAKE_REQUIRED_INCLUDES ${ZLIB_INCLUDE_DIRS})
endif()

option(CURL_BROTLI "Set to ON to enable building curl with brotli support." OFF)
set(HAVE_BROTLI OFF)
if(CURL_BROTLI)
  find_package(Brotli REQUIRED)
  if(BROTLI_FOUND)
    set(HAVE_BROTLI ON)
    set(CURL_LIBS "${BROTLI_LIBRARIES};${CURL_LIBS}")  # For 'ld' linker. Emulate `list(PREPEND ...)` to stay compatible with <v3.15 CMake.
    list(APPEND CURL_LIBS ${BROTLI_LIBRARIES})
    include_directories(${BROTLI_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_INCLUDES ${BROTLI_INCLUDE_DIRS})
  endif()
endif()

option(CURL_ZSTD "Set to ON to enable building curl with zstd support." OFF)
set(HAVE_ZSTD OFF)
if(CURL_ZSTD)
  find_package(Zstd REQUIRED)
  if(Zstd_FOUND AND NOT Zstd_VERSION VERSION_LESS "1.0.0")
    set(HAVE_ZSTD ON)
    list(APPEND CURL_LIBS ${Zstd_LIBRARIES})
    include_directories(${Zstd_INCLUDE_DIRS})
  else()
    message(WARNING "zstd v1.0.0 or newer is required, disabling zstd support.")
  endif()
endif()

# Check symbol in OpenSSL-like TLS backends.
macro(openssl_check_symbol_exists SYMBOL FILES VARIABLE)
  cmake_push_check_state()
  if(USE_OPENSSL)
    set(CMAKE_REQUIRED_INCLUDES   "${OPENSSL_INCLUDE_DIR}")
    set(CMAKE_REQUIRED_LIBRARIES  "${OPENSSL_LIBRARIES}")
    if(HAVE_LIBZ)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "${ZLIB_LIBRARIES}")
    endif()
    if(WIN32)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "ws2_32")
      list(APPEND CMAKE_REQUIRED_LIBRARIES "bcrypt")  # for OpenSSL/LibreSSL
    endif()
  elseif(USE_WOLFSSL)
    set(CMAKE_REQUIRED_INCLUDES   "${WolfSSL_INCLUDE_DIRS}")
    set(CMAKE_REQUIRED_LIBRARIES  "${WolfSSL_LIBRARIES}")
    if(HAVE_LIBZ)
      list(APPEND CMAKE_REQUIRED_INCLUDES  "${ZLIB_INCLUDE_DIRS}")  # Public wolfSSL headers require zlib headers
      list(APPEND CMAKE_REQUIRED_LIBRARIES "${ZLIB_LIBRARIES}")
    endif()
    if(WIN32)
      list(APPEND CMAKE_REQUIRED_LIBRARIES "ws2_32" "crypt32")
    endif()
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_UINTPTR_T)  # to pull in stdint.h (as of wolfSSL v5.5.4)
  endif()
  check_symbol_exists("${SYMBOL}" "${FILES}" "${VARIABLE}")
  cmake_pop_check_state()
endmacro()

# Ensure that the OpenSSL fork actually supports QUIC.
macro(openssl_check_quic)
  if(NOT DEFINED HAVE_SSL_CTX_SET_QUIC_METHOD)
    if(USE_OPENSSL)
      openssl_check_symbol_exists(SSL_CTX_set_quic_method "openssl/ssl.h" HAVE_SSL_CTX_SET_QUIC_METHOD)
    elseif(USE_WOLFSSL)
      openssl_check_symbol_exists(wolfSSL_set_quic_method "wolfssl/options.h;wolfssl/openssl/ssl.h" HAVE_SSL_CTX_SET_QUIC_METHOD)
    endif()
  endif()
  if(NOT HAVE_SSL_CTX_SET_QUIC_METHOD)
    message(FATAL_ERROR "QUIC support is missing in OpenSSL fork. Try setting -DOPENSSL_ROOT_DIR")
  endif()
endmacro()

if(USE_OPENSSL OR USE_WOLFSSL)
  if(NOT DEFINED HAVE_SSL_SET0_WBIO)
    openssl_check_symbol_exists(SSL_set0_wbio "openssl/ssl.h" HAVE_SSL_SET0_WBIO)
  endif()
  if(NOT DEFINED HAVE_OPENSSL_SRP AND NOT CURL_DISABLE_SRP)
    openssl_check_symbol_exists(SSL_CTX_set_srp_username "openssl/ssl.h" HAVE_OPENSSL_SRP)
  endif()
endif()

option(USE_NGHTTP2 "Use nghttp2 library" OFF)
if(USE_NGHTTP2)
  find_package(NGHTTP2 REQUIRED)
  include_directories(${NGHTTP2_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGHTTP2_LIBRARIES})
endif()

option(USE_NGTCP2 "Use ngtcp2 and nghttp3 libraries for HTTP/3 support" OFF)
if(USE_NGTCP2)
  if(USE_OPENSSL OR USE_WOLFSSL)
    if(USE_WOLFSSL)
      find_package(NGTCP2 REQUIRED wolfSSL)
    elseif(HAVE_BORINGSSL OR HAVE_AWSLC)
      find_package(NGTCP2 REQUIRED BoringSSL)
    else()
      find_package(NGTCP2 REQUIRED quictls)
    endif()
    openssl_check_quic()
  elseif(USE_GNUTLS)
    find_package(NGTCP2 REQUIRED GnuTLS)
  else()
    message(FATAL_ERROR "ngtcp2 requires OpenSSL, wolfSSL or GnuTLS")
  endif()
  set(USE_NGTCP2 ON)
  include_directories(${NGTCP2_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGTCP2_LIBRARIES})

  find_package(NGHTTP3 REQUIRED)
  set(USE_NGHTTP3 ON)
  include_directories(${NGHTTP3_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGHTTP3_LIBRARIES})
endif()

option(USE_QUICHE "Use quiche library for HTTP/3 support" OFF)
if(USE_QUICHE)
  if(USE_NGTCP2)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected!")
  endif()
  find_package(QUICHE REQUIRED)
  if(NOT HAVE_BORINGSSL)
    message(FATAL_ERROR "quiche requires BoringSSL")
  endif()
  openssl_check_quic()
  set(USE_QUICHE ON)
  include_directories(${QUICHE_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${QUICHE_LIBRARIES})
  if(NOT DEFINED HAVE_QUICHE_CONN_SET_QLOG_FD)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES   "${QUICHE_INCLUDE_DIRS}")
    set(CMAKE_REQUIRED_LIBRARIES  "${QUICHE_LIBRARIES}")
    check_symbol_exists(quiche_conn_set_qlog_fd "quiche.h" HAVE_QUICHE_CONN_SET_QLOG_FD)
    cmake_pop_check_state()
  endif()
endif()

option(USE_MSH3 "Use msquic library for HTTP/3 support" OFF)
if(USE_MSH3)
  if(USE_NGTCP2 OR USE_QUICHE)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected!")
  endif()
  set(USE_MSH3 ON)
  include_directories(${MSH3_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${MSH3_LIBRARIES})
endif()

option(USE_OPENSSL_QUIC "Use openssl and nghttp3 libraries for HTTP/3 support" OFF)
if(USE_OPENSSL_QUIC)
  if(USE_NGTCP2 OR USE_QUICHE OR USE_MSH3)
    message(FATAL_ERROR "Only one HTTP/3 backend can be selected!")
  endif()
  find_package(OpenSSL 3.2.0 REQUIRED)

  find_package(NGHTTP3 REQUIRED)
  set(USE_NGHTTP3 ON)
  include_directories(${NGHTTP3_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGHTTP3_LIBRARIES})
endif()

if(USE_MBEDTLS OR
   USE_BEARSSL OR
   USE_SECTRANSP)
  message(WARNING "A selected TLS library does not support TLS 1.3.")
endif()

if(CURL_WITH_MULTI_SSL AND (USE_NGTCP2 OR USE_QUICHE OR USE_MSH3 OR USE_OPENSSL_QUIC))
  message(FATAL_ERROR "MultiSSL cannot be enabled with HTTP/3 and vice versa.")
endif()

if(NOT CURL_DISABLE_SRP AND (HAVE_GNUTLS_SRP OR HAVE_OPENSSL_SRP))
  set(USE_TLS_SRP 1)
endif()

if(NOT CURL_DISABLE_LDAP)
  if(WIN32)
    option(USE_WIN32_LDAP "Use Windows LDAP implementation" ON)
    if(USE_WIN32_LDAP)
      list(APPEND CURL_LIBS "wldap32")
      if(NOT CURL_DISABLE_LDAPS)
        set(HAVE_LDAP_SSL ON)
      endif()
    endif()
  endif()

  set(CMAKE_LDAP_LIB "ldap" CACHE STRING "Name or full path to ldap library")
  set(CMAKE_LBER_LIB "lber" CACHE STRING "Name or full path to lber library")

  # Now that we know, we're not using windows LDAP...
  if(NOT USE_WIN32_LDAP)
    # Check for LDAP
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    check_library_exists("${CMAKE_LDAP_LIB}" "ldap_init" "" HAVE_LIBLDAP)
    if(HAVE_LIBLDAP)
      check_library_exists("${CMAKE_LDAP_LIB};${CMAKE_LBER_LIB}" "ber_init" "" HAVE_LIBLBER)
    else()
      check_library_exists("${CMAKE_LBER_LIB}" "ber_init" "" HAVE_LIBLBER)
    endif()

    set(CMAKE_REQUIRED_INCLUDES_BAK ${CMAKE_REQUIRED_INCLUDES})
    set(CMAKE_LDAP_INCLUDE_DIR "" CACHE STRING "Path to LDAP include directory")
    if(CMAKE_LDAP_INCLUDE_DIR)
      list(APPEND CMAKE_REQUIRED_INCLUDES ${CMAKE_LDAP_INCLUDE_DIR})
    endif()
    check_include_file_concat("ldap.h"           HAVE_LDAP_H)
    check_include_file_concat("lber.h"           HAVE_LBER_H)

    if(NOT HAVE_LDAP_H)
      message(STATUS "LDAP_H not found CURL_DISABLE_LDAP set ON")
      set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
      set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_BAK}) #LDAP includes won't be used
    elseif(NOT HAVE_LIBLDAP)
      message(STATUS "LDAP library '${CMAKE_LDAP_LIB}' not found CURL_DISABLE_LDAP set ON")
      set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
      set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_BAK}) #LDAP includes won't be used
    else()
      if(CMAKE_LDAP_INCLUDE_DIR)
        include_directories(${CMAKE_LDAP_INCLUDE_DIR})
      endif()
      set(NEED_LBER_H ON)
      set(_HEADER_LIST)
      if(WIN32)
        list(APPEND _HEADER_LIST "windows.h")
      endif()
      if(HAVE_SYS_TYPES_H)
        list(APPEND _HEADER_LIST "sys/types.h")
      endif()
      list(APPEND _HEADER_LIST "ldap.h")

      set(_INCLUDE_STRING "")
      foreach(_HEADER ${_HEADER_LIST})
        set(_INCLUDE_STRING "${_INCLUDE_STRING}#include <${_HEADER}>\n")
      endforeach()

      list(APPEND CMAKE_REQUIRED_DEFINITIONS -DLDAP_DEPRECATED=1)
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_LDAP_LIB})
      set(CURL_LIBS "${CMAKE_LDAP_LIB};${CURL_LIBS}")
      if(HAVE_LIBLBER)
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_LBER_LIB})
        set(CURL_LIBS "${CMAKE_LBER_LIB};${CURL_LIBS}")
      endif()

      check_c_source_compiles("
        ${_INCLUDE_STRING}
        int main(int argc, char ** argv)
        {
          BerValue *bvp = NULL;
          BerElement *bep = ber_init(bvp);
          ber_free(bep, 1);
          return 0;
        }" NOT_NEED_LBER_H)
      if(NOT_NEED_LBER_H)
        set(NEED_LBER_H OFF)
      else()
        set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -DNEED_LBER_H")
      endif()

      check_function_exists(ldap_url_parse HAVE_LDAP_URL_PARSE)
      check_function_exists(ldap_init_fd HAVE_LDAP_INIT_FD)

      unset(CMAKE_REQUIRED_LIBRARIES)

      check_include_file("ldap_ssl.h" HAVE_LDAP_SSL_H)

      if(HAVE_LDAP_INIT_FD)
        set(USE_OPENLDAP ON)
        add_definitions("-DLDAP_DEPRECATED=1")
      endif()
      if(NOT CURL_DISABLE_LDAPS)
        set(HAVE_LDAP_SSL ON)
      endif()
    endif()
  endif()
endif()

# No ldap, no ldaps.
if(CURL_DISABLE_LDAP)
  if(NOT CURL_DISABLE_LDAPS)
    message(STATUS "LDAP needs to be enabled to support LDAPS")
    set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)
  endif()
endif()

# Check for idn2
option(USE_LIBIDN2 "Use libidn2 for IDN support" ON)
if(USE_LIBIDN2)
  check_library_exists("idn2" "idn2_lookup_ul" "" HAVE_LIBIDN2)
  if(HAVE_LIBIDN2)
    set(CURL_LIBS "idn2;${CURL_LIBS}")
    check_include_file_concat("idn2.h" HAVE_IDN2_H)
  endif()
else()
  set(HAVE_LIBIDN2 OFF)
endif()

if(WIN32)
  option(USE_WIN32_IDN "Use WinIDN for IDN support" OFF)
  if(USE_WIN32_IDN)
    list(APPEND CURL_LIBS "normaliz")
  endif()
endif()

#libpsl
option(CURL_USE_LIBPSL "Use libPSL" ON)
mark_as_advanced(CURL_USE_LIBPSL)
set(USE_LIBPSL OFF)

if(CURL_USE_LIBPSL)
  find_package(LibPSL)
  if(LIBPSL_FOUND)
    list(APPEND CURL_LIBS ${LIBPSL_LIBRARY})
    list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBPSL_INCLUDE_DIR}")
    include_directories("${LIBPSL_INCLUDE_DIR}")
    set(USE_LIBPSL ON)
  endif()
endif()

#libSSH2
option(CURL_USE_LIBSSH2 "Use libSSH2" ON)
mark_as_advanced(CURL_USE_LIBSSH2)
set(USE_LIBSSH2 OFF)

if(CURL_USE_LIBSSH2)
  find_package(LibSSH2)
  if(LIBSSH2_FOUND)
    list(APPEND CURL_LIBS ${LIBSSH2_LIBRARY})
    list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBSSH2_INCLUDE_DIR}")
    include_directories("${LIBSSH2_INCLUDE_DIR}")
    set(USE_LIBSSH2 ON)
  endif()
endif()

# libssh
option(CURL_USE_LIBSSH "Use libSSH" OFF)
mark_as_advanced(CURL_USE_LIBSSH)
if(NOT USE_LIBSSH2 AND CURL_USE_LIBSSH)
  find_package(libssh CONFIG)
  if(libssh_FOUND)
    message(STATUS "Found libssh ${libssh_VERSION}")
    # Use imported target for include and library paths.
    list(APPEND CURL_LIBS ssh)
    set(USE_LIBSSH ON)
  endif()
endif()

option(CURL_USE_GSSAPI "Use GSSAPI implementation (right now only Heimdal is supported with CMake build)" OFF)
mark_as_advanced(CURL_USE_GSSAPI)

if(CURL_USE_GSSAPI)
  find_package(GSS)

  set(HAVE_GSSAPI ${GSS_FOUND})
  if(GSS_FOUND)

    message(STATUS "Found ${GSS_FLAVOUR} GSSAPI version: \"${GSS_VERSION}\"")

    list(APPEND CMAKE_REQUIRED_INCLUDES ${GSS_INCLUDE_DIR})
    check_include_file_concat("gssapi/gssapi.h"  HAVE_GSSAPI_GSSAPI_H)
    check_include_file_concat("gssapi/gssapi_generic.h" HAVE_GSSAPI_GSSAPI_GENERIC_H)
    check_include_file_concat("gssapi/gssapi_krb5.h" HAVE_GSSAPI_GSSAPI_KRB5_H)

    if(NOT GSS_FLAVOUR STREQUAL "Heimdal")
      # MIT
      set(_INCLUDE_LIST "")
      if(HAVE_GSSAPI_GSSAPI_H)
        list(APPEND _INCLUDE_LIST "gssapi/gssapi.h")
      endif()
      if(HAVE_GSSAPI_GSSAPI_GENERIC_H)
        list(APPEND _INCLUDE_LIST "gssapi/gssapi_generic.h")
      endif()
      if(HAVE_GSSAPI_GSSAPI_KRB5_H)
        list(APPEND _INCLUDE_LIST "gssapi/gssapi_krb5.h")
      endif()

      string(REPLACE ";" " " _COMPILER_FLAGS_STR "${GSS_COMPILER_FLAGS}")
      string(REPLACE ";" " " _LINKER_FLAGS_STR "${GSS_LINKER_FLAGS}")

      foreach(_dir ${GSS_LINK_DIRECTORIES})
        set(_LINKER_FLAGS_STR "${_LINKER_FLAGS_STR} -L\"${_dir}\"")
      endforeach()

      if(NOT DEFINED HAVE_GSS_C_NT_HOSTBASED_SERVICE)
        set(CMAKE_REQUIRED_FLAGS "${_COMPILER_FLAGS_STR} ${_LINKER_FLAGS_STR}")
        set(CMAKE_REQUIRED_LIBRARIES ${GSS_LIBRARIES})
        check_symbol_exists("GSS_C_NT_HOSTBASED_SERVICE" ${_INCLUDE_LIST} HAVE_GSS_C_NT_HOSTBASED_SERVICE)
        unset(CMAKE_REQUIRED_LIBRARIES)
      endif()
      if(NOT HAVE_GSS_C_NT_HOSTBASED_SERVICE)
        set(HAVE_OLD_GSSMIT ON)
      endif()
    endif()

    include_directories(${GSS_INCLUDE_DIR})
    link_directories(${GSS_LINK_DIRECTORIES})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GSS_COMPILER_FLAGS}")
    string(REPLACE ";" " " GSS_LINKER_FLAGS "${GSS_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GSS_LINKER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GSS_LINKER_FLAGS}")
    set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} ${GSS_LINKER_FLAGS}")
    list(APPEND CURL_LIBS ${GSS_LIBRARIES})

  else()
    message(WARNING "GSSAPI support has been requested but no supporting libraries found. Skipping.")
  endif()
endif()

option(ENABLE_UNIX_SOCKETS "Define if you want Unix domain sockets support" ON)
if(ENABLE_UNIX_SOCKETS)
  include(CheckStructHasMember)
  if(WIN32)
    set(USE_UNIX_SOCKETS ON)
  else()
    check_struct_has_member("struct sockaddr_un" sun_path "sys/un.h" USE_UNIX_SOCKETS)
  endif()
else()
  unset(USE_UNIX_SOCKETS CACHE)
endif()


#
# CA handling
#
set(CURL_CA_BUNDLE "auto" CACHE STRING
    "Path to the CA bundle. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
set(CURL_CA_FALLBACK OFF CACHE BOOL
    "Set ON to use built-in CA store of TLS backend. Defaults to OFF")
set(CURL_CA_PATH "auto" CACHE STRING
    "Location of default CA path. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")

if("${CURL_CA_BUNDLE}" STREQUAL "")
  message(FATAL_ERROR "Invalid value of CURL_CA_BUNDLE. Use 'none', 'auto' or file path.")
elseif("${CURL_CA_BUNDLE}" STREQUAL "none")
  unset(CURL_CA_BUNDLE CACHE)
elseif("${CURL_CA_BUNDLE}" STREQUAL "auto")
  unset(CURL_CA_BUNDLE CACHE)
  if(NOT CMAKE_CROSSCOMPILING)
    set(CURL_CA_BUNDLE_AUTODETECT TRUE)
  endif()
else()
  set(CURL_CA_BUNDLE_SET TRUE)
endif()

if("${CURL_CA_PATH}" STREQUAL "")
  message(FATAL_ERROR "Invalid value of CURL_CA_PATH. Use 'none', 'auto' or directory path.")
elseif("${CURL_CA_PATH}" STREQUAL "none")
  unset(CURL_CA_PATH CACHE)
elseif("${CURL_CA_PATH}" STREQUAL "auto")
  unset(CURL_CA_PATH CACHE)
  if(NOT CMAKE_CROSSCOMPILING)
    set(CURL_CA_PATH_AUTODETECT TRUE)
  endif()
else()
  set(CURL_CA_PATH_SET TRUE)
endif()

if(CURL_CA_BUNDLE_SET AND CURL_CA_PATH_AUTODETECT)
  # Skip autodetection of unset CA path because CA bundle is set explicitly
elseif(CURL_CA_PATH_SET AND CURL_CA_BUNDLE_AUTODETECT)
  # Skip autodetection of unset CA bundle because CA path is set explicitly
elseif(CURL_CA_PATH_AUTODETECT OR CURL_CA_BUNDLE_AUTODETECT)
  # first try autodetecting a CA bundle, then a CA path

  if(CURL_CA_BUNDLE_AUTODETECT)
    set(SEARCH_CA_BUNDLE_PATHS
        /etc/ssl/certs/ca-certificates.crt
        /etc/pki/tls/certs/ca-bundle.crt
        /usr/share/ssl/certs/ca-bundle.crt
        /usr/local/share/certs/ca-root-nss.crt
        /etc/ssl/cert.pem)

    foreach(SEARCH_CA_BUNDLE_PATH ${SEARCH_CA_BUNDLE_PATHS})
      if(EXISTS "${SEARCH_CA_BUNDLE_PATH}")
        message(STATUS "Found CA bundle: ${SEARCH_CA_BUNDLE_PATH}")
        set(CURL_CA_BUNDLE "${SEARCH_CA_BUNDLE_PATH}" CACHE STRING
            "Path to the CA bundle. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
        set(CURL_CA_BUNDLE_SET TRUE CACHE BOOL "Path to the CA bundle has been set")
        break()
      endif()
    endforeach()
  endif()

  if(CURL_CA_PATH_AUTODETECT AND (NOT CURL_CA_PATH_SET))
    if(EXISTS "/etc/ssl/certs")
      set(CURL_CA_PATH "/etc/ssl/certs" CACHE STRING
          "Location of default CA path. Set 'none' to disable or 'auto' for auto-detection. Defaults to 'auto'.")
      set(CURL_CA_PATH_SET TRUE CACHE BOOL "Path to the CA bundle has been set")
    endif()
  endif()
endif()

if(CURL_CA_PATH_SET AND
   NOT USE_OPENSSL AND
   NOT USE_WOLFSSL AND
   NOT USE_GNUTLS AND
   NOT USE_MBEDTLS)
  message(STATUS
          "CA path only supported by OpenSSL, wolfSSL, GnuTLS or mbedTLS. "
          "Set CURL_CA_PATH=none or enable one of those TLS backends.")
endif()

# Check for header files
if(WIN32)
  set(CURL_INCLUDES ${CURL_INCLUDES} "winsock2.h")
  set(CURL_INCLUDES ${CURL_INCLUDES} "ws2tcpip.h")
  set(CURL_INCLUDES ${CURL_INCLUDES} "windows.h")
endif()

if(WIN32)
  # detect actual value of _WIN32_WINNT and store as HAVE_WIN32_WINNT
  curl_internal_test(HAVE_WIN32_WINNT)
  if(HAVE_WIN32_WINNT)
    string(REGEX MATCH ".*_WIN32_WINNT=0x[0-9a-fA-F]+" OUTPUT "${OUTPUT}")
    string(REGEX REPLACE ".*_WIN32_WINNT=" "" OUTPUT "${OUTPUT}")
    string(REGEX REPLACE "0x([0-9a-f][0-9a-f][0-9a-f])$" "0x0\\1" OUTPUT "${OUTPUT}")  # pad to 4 digits
    string(TOLOWER "${OUTPUT}" HAVE_WIN32_WINNT)
    message(STATUS "Found _WIN32_WINNT=${HAVE_WIN32_WINNT}")
  endif()
  # avoid storing HAVE_WIN32_WINNT in CMake cache
  unset(HAVE_WIN32_WINNT CACHE)

  if(HAVE_WIN32_WINNT)
    if(HAVE_WIN32_WINNT STRLESS "0x0501")
      # Windows XP is required for freeaddrinfo, getaddrinfo
      message(FATAL_ERROR "Building for Windows XP or newer is required.")
    endif()

    # pre-fill detection results based on target OS version
    if(MINGW OR MSVC)
      if(HAVE_WIN32_WINNT STRLESS "0x0600")
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

check_include_file_concat("sys/filio.h"      HAVE_SYS_FILIO_H)
check_include_file_concat("sys/wait.h"       HAVE_SYS_WAIT_H)
check_include_file_concat("sys/ioctl.h"      HAVE_SYS_IOCTL_H)
check_include_file_concat("sys/param.h"      HAVE_SYS_PARAM_H)
check_include_file_concat("sys/poll.h"       HAVE_SYS_POLL_H)
check_include_file_concat("sys/resource.h"   HAVE_SYS_RESOURCE_H)
check_include_file_concat("sys/select.h"     HAVE_SYS_SELECT_H)
check_include_file_concat("sys/socket.h"     HAVE_SYS_SOCKET_H)
check_include_file_concat("sys/sockio.h"     HAVE_SYS_SOCKIO_H)
check_include_file_concat("sys/stat.h"       HAVE_SYS_STAT_H)
check_include_file_concat("sys/time.h"       HAVE_SYS_TIME_H)
check_include_file_concat("sys/types.h"      HAVE_SYS_TYPES_H)
check_include_file_concat("sys/un.h"         HAVE_SYS_UN_H)
check_include_file_concat("sys/utime.h"      HAVE_SYS_UTIME_H)
check_include_file_concat("sys/xattr.h"      HAVE_SYS_XATTR_H)
check_include_file_concat("arpa/inet.h"      HAVE_ARPA_INET_H)
check_include_file_concat("fcntl.h"          HAVE_FCNTL_H)
check_include_file_concat("ifaddrs.h"        HAVE_IFADDRS_H)
check_include_file_concat("io.h"             HAVE_IO_H)
check_include_file_concat("libgen.h"         HAVE_LIBGEN_H)
check_include_file_concat("locale.h"         HAVE_LOCALE_H)
check_include_file_concat("net/if.h"         HAVE_NET_IF_H)
check_include_file_concat("netdb.h"          HAVE_NETDB_H)
check_include_file_concat("netinet/in.h"     HAVE_NETINET_IN_H)
check_include_file_concat("netinet/tcp.h"    HAVE_NETINET_TCP_H)
check_include_file_concat("netinet/udp.h"    HAVE_NETINET_UDP_H)
check_include_file("linux/tcp.h"      HAVE_LINUX_TCP_H)

check_include_file_concat("poll.h"           HAVE_POLL_H)
check_include_file_concat("pwd.h"            HAVE_PWD_H)
check_include_file_concat("stdatomic.h"      HAVE_STDATOMIC_H)
check_include_file_concat("stdbool.h"        HAVE_STDBOOL_H)
check_include_file_concat("strings.h"        HAVE_STRINGS_H)
check_include_file_concat("stropts.h"        HAVE_STROPTS_H)
check_include_file_concat("termio.h"         HAVE_TERMIO_H)
check_include_file_concat("termios.h"        HAVE_TERMIOS_H)
check_include_file_concat("unistd.h"         HAVE_UNISTD_H)
check_include_file_concat("utime.h"          HAVE_UTIME_H)

check_type_size(size_t  SIZEOF_SIZE_T)
check_type_size(ssize_t  SIZEOF_SSIZE_T)
check_type_size("long long"  SIZEOF_LONG_LONG)
check_type_size("long"  SIZEOF_LONG)
check_type_size("int"  SIZEOF_INT)
check_type_size("__int64"  SIZEOF___INT64)
check_type_size("time_t"  SIZEOF_TIME_T)
check_type_size("suseconds_t"  SIZEOF_SUSECONDS_T)
if(NOT HAVE_SIZEOF_SSIZE_T)
  if(SIZEOF_LONG EQUAL SIZEOF_SIZE_T)
    set(ssize_t long)
  endif()
  if(NOT ssize_t AND SIZEOF___INT64 EQUAL SIZEOF_SIZE_T)
    set(ssize_t __int64)
  endif()
endif()
# off_t is sized later, after the HAVE_FILE_OFFSET_BITS test

if(SIZEOF_LONG_LONG)
  set(HAVE_LONGLONG 1)
endif()
if(SIZEOF_SUSECONDS_T)
  set(HAVE_SUSECONDS_T 1)
endif()

if(NOT CMAKE_CROSSCOMPILING)
  find_file(RANDOM_FILE urandom /dev)
  mark_as_advanced(RANDOM_FILE)
endif()

# Check for some functions that are used
if(WIN32)
  set(CMAKE_REQUIRED_LIBRARIES ws2_32)
elseif(HAVE_LIBSOCKET)
  set(CMAKE_REQUIRED_LIBRARIES socket)
endif()

check_symbol_exists(fnmatch       "${CURL_INCLUDES};fnmatch.h" HAVE_FNMATCH)
check_symbol_exists(basename      "${CURL_INCLUDES};string.h" HAVE_BASENAME)
check_symbol_exists(socket        "${CURL_INCLUDES}" HAVE_SOCKET)
check_symbol_exists(sched_yield   "${CURL_INCLUDES};sched.h" HAVE_SCHED_YIELD)
check_symbol_exists(socketpair    "${CURL_INCLUDES}" HAVE_SOCKETPAIR)
check_symbol_exists(recv          "${CURL_INCLUDES}" HAVE_RECV)
check_symbol_exists(send          "${CURL_INCLUDES}" HAVE_SEND)
check_symbol_exists(sendmsg       "${CURL_INCLUDES}" HAVE_SENDMSG)
check_symbol_exists(select        "${CURL_INCLUDES}" HAVE_SELECT)
check_symbol_exists(strdup        "${CURL_INCLUDES};string.h" HAVE_STRDUP)
check_symbol_exists(strtok_r      "${CURL_INCLUDES};string.h" HAVE_STRTOK_R)
check_symbol_exists(strcasecmp    "${CURL_INCLUDES};string.h" HAVE_STRCASECMP)
check_symbol_exists(stricmp       "${CURL_INCLUDES};string.h" HAVE_STRICMP)
check_symbol_exists(strcmpi       "${CURL_INCLUDES};string.h" HAVE_STRCMPI)
check_symbol_exists(memrchr       "${CURL_INCLUDES};string.h" HAVE_MEMRCHR)
check_symbol_exists(alarm         "${CURL_INCLUDES}" HAVE_ALARM)
check_symbol_exists(arc4random    "${CURL_INCLUDES};stdlib.h" HAVE_ARC4RANDOM)
check_symbol_exists(fcntl         "${CURL_INCLUDES}" HAVE_FCNTL)
check_symbol_exists(getppid       "${CURL_INCLUDES}" HAVE_GETPPID)
check_symbol_exists(utimes        "${CURL_INCLUDES}" HAVE_UTIMES)

check_symbol_exists(gettimeofday  "${CURL_INCLUDES}" HAVE_GETTIMEOFDAY)
check_symbol_exists(closesocket   "${CURL_INCLUDES}" HAVE_CLOSESOCKET)
check_symbol_exists(sigsetjmp     "${CURL_INCLUDES};setjmp.h" HAVE_SIGSETJMP)
check_symbol_exists(getpass_r     "${CURL_INCLUDES}" HAVE_GETPASS_R)
check_symbol_exists(getpwuid      "${CURL_INCLUDES}" HAVE_GETPWUID)
check_symbol_exists(getpwuid_r    "${CURL_INCLUDES}" HAVE_GETPWUID_R)
check_symbol_exists(geteuid       "${CURL_INCLUDES}" HAVE_GETEUID)
check_symbol_exists(utime         "${CURL_INCLUDES}" HAVE_UTIME)
check_symbol_exists(gmtime_r      "${CURL_INCLUDES};stdlib.h;time.h" HAVE_GMTIME_R)

check_symbol_exists(gethostbyname_r "${CURL_INCLUDES}" HAVE_GETHOSTBYNAME_R)

check_symbol_exists(signal         "${CURL_INCLUDES};signal.h" HAVE_SIGNAL)
check_symbol_exists(strtoll        "${CURL_INCLUDES};stdlib.h" HAVE_STRTOLL)
check_symbol_exists(strerror_r     "${CURL_INCLUDES};stdlib.h;string.h" HAVE_STRERROR_R)
check_symbol_exists(sigaction      "signal.h" HAVE_SIGACTION)
check_symbol_exists(siginterrupt   "${CURL_INCLUDES};signal.h" HAVE_SIGINTERRUPT)
check_symbol_exists(getaddrinfo    "${CURL_INCLUDES};stdlib.h;string.h" HAVE_GETADDRINFO)
check_symbol_exists(getifaddrs     "${CURL_INCLUDES};stdlib.h" HAVE_GETIFADDRS)
check_symbol_exists(freeaddrinfo   "${CURL_INCLUDES}" HAVE_FREEADDRINFO)
check_symbol_exists(pipe           "${CURL_INCLUDES}" HAVE_PIPE)
check_symbol_exists(ftruncate      "${CURL_INCLUDES}" HAVE_FTRUNCATE)
check_symbol_exists(fseeko         "${CURL_INCLUDES};stdio.h" HAVE_FSEEKO)
check_symbol_exists(_fseeki64      "${CURL_INCLUDES};stdio.h" HAVE__FSEEKI64)
check_symbol_exists(getpeername    "${CURL_INCLUDES}" HAVE_GETPEERNAME)
check_symbol_exists(getsockname    "${CURL_INCLUDES}" HAVE_GETSOCKNAME)
check_symbol_exists(if_nametoindex "${CURL_INCLUDES}" HAVE_IF_NAMETOINDEX)
check_symbol_exists(getrlimit      "${CURL_INCLUDES}" HAVE_GETRLIMIT)
check_symbol_exists(setlocale      "${CURL_INCLUDES}" HAVE_SETLOCALE)
check_symbol_exists(setmode        "${CURL_INCLUDES}" HAVE_SETMODE)
check_symbol_exists(setrlimit      "${CURL_INCLUDES}" HAVE_SETRLIMIT)

if(HAVE_FSEEKO)
  set(HAVE_DECL_FSEEKO 1)
endif()

if(NOT MSVC OR (MSVC_VERSION GREATER_EQUAL 1900))
  # earlier MSVC compilers had faulty snprintf implementations
  check_symbol_exists(snprintf       "stdio.h" HAVE_SNPRINTF)
endif()
check_function_exists(mach_absolute_time HAVE_MACH_ABSOLUTE_TIME)
check_symbol_exists(inet_ntop      "${CURL_INCLUDES};stdlib.h;string.h" HAVE_INET_NTOP)
if(MSVC AND (MSVC_VERSION LESS_EQUAL 1600))
  set(HAVE_INET_NTOP OFF)
endif()
check_symbol_exists(inet_pton      "${CURL_INCLUDES};stdlib.h;string.h" HAVE_INET_PTON)

check_symbol_exists(fsetxattr "${CURL_INCLUDES}" HAVE_FSETXATTR)
if(HAVE_FSETXATTR)
  foreach(CURL_TEST HAVE_FSETXATTR_5 HAVE_FSETXATTR_6)
    curl_internal_test(${CURL_TEST})
  endforeach()
endif()

set(CMAKE_EXTRA_INCLUDE_FILES   "sys/socket.h")
check_type_size("sa_family_t"   SIZEOF_SA_FAMILY_T)
set(HAVE_SA_FAMILY_T            ${HAVE_SIZEOF_SA_FAMILY_T})
set(CMAKE_EXTRA_INCLUDE_FILES   "")

if(WIN32)
  set(CMAKE_EXTRA_INCLUDE_FILES   "winsock2.h")
  check_type_size("ADDRESS_FAMILY"    SIZEOF_ADDRESS_FAMILY)
  set(HAVE_ADDRESS_FAMILY         ${HAVE_SIZEOF_ADDRESS_FAMILY})
  set(CMAKE_EXTRA_INCLUDE_FILES   "")
endif()

# Do curl specific tests
foreach(CURL_TEST
    HAVE_FCNTL_O_NONBLOCK
    HAVE_IOCTLSOCKET
    HAVE_IOCTLSOCKET_CAMEL
    HAVE_IOCTLSOCKET_CAMEL_FIONBIO
    HAVE_IOCTLSOCKET_FIONBIO
    HAVE_IOCTL_FIONBIO
    HAVE_IOCTL_SIOCGIFADDR
    HAVE_SETSOCKOPT_SO_NONBLOCK
    HAVE_O_NONBLOCK
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
  curl_internal_test(${CURL_TEST})
endforeach()

if(HAVE_FILE_OFFSET_BITS)
  set(_FILE_OFFSET_BITS 64)
  set(CMAKE_REQUIRED_FLAGS "-D_FILE_OFFSET_BITS=64")
endif()
check_type_size("off_t"  SIZEOF_OFF_T)

# include this header to get the type
set(CMAKE_REQUIRED_INCLUDES "${CURL_SOURCE_DIR}/include")
set(CMAKE_EXTRA_INCLUDE_FILES "curl/system.h")
check_type_size("curl_off_t"  SIZEOF_CURL_OFF_T)
set(CMAKE_EXTRA_INCLUDE_FILES "curl/curl.h")
check_type_size("curl_socket_t"  SIZEOF_CURL_SOCKET_T)
set(CMAKE_EXTRA_INCLUDE_FILES "")

if(NOT WIN32 AND NOT CMAKE_CROSSCOMPILING)
  # on not-Windows and not-crosscompiling, check for writable argv[]
  include(CheckCSourceRuns)
  check_c_source_runs("
    int main(int argc, char **argv)
    {
      (void)argc;
      argv[0][0] = ' ';
      return (argv[0][0] == ' ')?0:1;
    }" HAVE_WRITABLE_ARGV)
endif()

set(CMAKE_REQUIRED_FLAGS)

option(ENABLE_WEBSOCKETS "Set to ON to enable EXPERIMENTAL websockets" OFF)

if(ENABLE_WEBSOCKETS)
  if(${SIZEOF_CURL_OFF_T} GREATER "4")
    set(USE_WEBSOCKETS ON)
  else()
    message(WARNING "curl_off_t is too small to enable WebSockets")
  endif()
endif()

foreach(CURL_TEST
    HAVE_GLIBC_STRERROR_R
    HAVE_POSIX_STRERROR_R
    )
  curl_internal_test(${CURL_TEST})
endforeach()

# Check for reentrant
foreach(CURL_TEST
    HAVE_GETHOSTBYNAME_R_3
    HAVE_GETHOSTBYNAME_R_5
    HAVE_GETHOSTBYNAME_R_6)
  if(NOT ${CURL_TEST})
    if(${CURL_TEST}_REENTRANT)
      set(NEED_REENTRANT 1)
    endif()
  endif()
endforeach()

if(NEED_REENTRANT)
  foreach(CURL_TEST
      HAVE_GETHOSTBYNAME_R_3
      HAVE_GETHOSTBYNAME_R_5
      HAVE_GETHOSTBYNAME_R_6)
    set(${CURL_TEST} 0)
    if(${CURL_TEST}_REENTRANT)
      set(${CURL_TEST} 1)
    endif()
  endforeach()
endif()

if(NOT WIN32)
  # Check clock_gettime(CLOCK_MONOTONIC, x) support
  curl_internal_test(HAVE_CLOCK_GETTIME_MONOTONIC)
endif()

# Check compiler support of __builtin_available()
curl_internal_test(HAVE_BUILTIN_AVAILABLE)

# Some other minor tests

if(NOT HAVE_IN_ADDR_T)
  set(in_addr_t "unsigned long")
endif()

# Check for nonblocking
set(HAVE_DISABLED_NONBLOCKING 1)
if(HAVE_FIONBIO OR
    HAVE_IOCTLSOCKET OR
    HAVE_IOCTLSOCKET_CASE OR
    HAVE_O_NONBLOCK)
  set(HAVE_DISABLED_NONBLOCKING)
endif()

if(CMAKE_COMPILER_IS_GNUCC AND APPLE)
  include(CheckCCompilerFlag)
  check_c_compiler_flag(-Wno-long-double HAVE_C_FLAG_Wno_long_double)
  if(HAVE_C_FLAG_Wno_long_double)
    # The Mac version of GCC warns about use of long double.  Disable it.
    get_source_file_property(MPRINTF_COMPILE_FLAGS mprintf.c COMPILE_FLAGS)
    if(MPRINTF_COMPILE_FLAGS)
      set(MPRINTF_COMPILE_FLAGS "${MPRINTF_COMPILE_FLAGS} -Wno-long-double")
    else()
      set(MPRINTF_COMPILE_FLAGS "-Wno-long-double")
    endif()
    set_source_files_properties(mprintf.c PROPERTIES
      COMPILE_FLAGS ${MPRINTF_COMPILE_FLAGS})
  endif()
endif()

include(CMake/OtherTests.cmake)

add_definitions(-DHAVE_CONFIG_H)

# For Windows, all compilers used by CMake should support large files
if(WIN32)
  set(USE_WIN32_LARGE_FILES ON)

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
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")

  add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
  if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  endif()

  # Use multithreaded compilation on VS 2008+
  if(MSVC_VERSION GREATER_EQUAL 1500)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
  endif()
endif()

if(CURL_WERROR)
  if(MSVC_VERSION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
  else()
    # this assumes clang or gcc style options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
  endif()
endif()

if(CURL_LTO)
  if(CMAKE_VERSION VERSION_LESS 3.9)
    message(FATAL_ERROR "Requested LTO but your cmake version ${CMAKE_VERSION} is to old. You need at least 3.9")
  endif()

  cmake_policy(SET CMP0069 NEW)

  include(CheckIPOSupported)
  check_ipo_supported(RESULT CURL_HAS_LTO OUTPUT CURL_LTO_ERROR LANGUAGES C)
  if(CURL_HAS_LTO)
    message(STATUS "LTO supported and enabled")
  else()
    message(FATAL_ERROR "LTO was requested - but compiler doesn't support it\n${CURL_LTO_ERROR}")
  endif()
endif()


# Ugly (but functional) way to include "Makefile.inc" by transforming it (= regenerate it).
function(transform_makefile_inc INPUT_FILE OUTPUT_FILE)
  file(READ ${INPUT_FILE} MAKEFILE_INC_TEXT)
  string(REPLACE "$(top_srcdir)"   "\${CURL_SOURCE_DIR}" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})
  string(REPLACE "$(top_builddir)" "\${CURL_BINARY_DIR}" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})

  string(REGEX REPLACE "\\\\\n" "!π!α!" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})
  string(REGEX REPLACE "([a-zA-Z_][a-zA-Z0-9_]*)[\t ]*=[\t ]*([^\n]*)" "SET(\\1 \\2)" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})
  string(REPLACE "!π!α!" "\n" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})

  string(REGEX REPLACE "\\$\\(([a-zA-Z_][a-zA-Z0-9_]*)\\)" "\${\\1}" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})    # Replace $() with ${}
  string(REGEX REPLACE "@([a-zA-Z_][a-zA-Z0-9_]*)@" "\${\\1}" MAKEFILE_INC_TEXT ${MAKEFILE_INC_TEXT})    # Replace @@ with ${}, even if that may not be read by CMake scripts.
  file(WRITE ${OUTPUT_FILE} ${MAKEFILE_INC_TEXT})
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${INPUT_FILE}")
endfunction()

include(GNUInstallDirs)

set(CURL_INSTALL_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")

if(HAVE_MANUAL_TOOLS)
  add_subdirectory(docs)
endif()

add_subdirectory(lib)

if(BUILD_CURL_EXE)
  add_subdirectory(src)
endif()

cmake_dependent_option(BUILD_TESTING "Build tests"
  ON "PERL_FOUND;NOT CURL_DISABLE_TESTS"
  OFF)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

if(NOT CURL_DISABLE_INSTALL)

  install(FILES "${PROJECT_SOURCE_DIR}/scripts/mk-ca-bundle.pl"
          DESTINATION ${CMAKE_INSTALL_BINDIR}
          PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)

  # Helper to populate a list (_items) with a label when conditions (the remaining
  # args) are satisfied
  macro(_add_if label)
    # needs to be a macro to allow this indirection
    if(${ARGN})
      set(_items ${_items} "${label}")
    endif()
  endmacro()

  # NTLM support requires crypto function adaptions from various SSL libs
  if(NOT (CURL_DISABLE_NTLM) AND
      (USE_OPENSSL OR USE_MBEDTLS OR USE_DARWINSSL OR USE_WIN32_CRYPTO OR USE_GNUTLS))
    set(use_curl_ntlm_core ON)
  endif()

  # Clear list and try to detect available features
  set(_items)
  _add_if("SSL"           SSL_ENABLED)
  _add_if("IPv6"          ENABLE_IPV6)
  _add_if("UnixSockets"   USE_UNIX_SOCKETS)
  _add_if("libz"          HAVE_LIBZ)
  _add_if("brotli"        HAVE_BROTLI)
  _add_if("zstd"          HAVE_ZSTD)
  _add_if("AsynchDNS"     USE_ARES OR USE_THREADS_POSIX OR USE_THREADS_WIN32)
  _add_if("IDN"           HAVE_LIBIDN2 OR USE_WIN32_IDN)
  _add_if("Largefile"     (SIZEOF_CURL_OFF_T GREATER 4) AND
                          ((SIZEOF_OFF_T GREATER 4) OR USE_WIN32_LARGE_FILES))
  _add_if("SSPI"          USE_WINDOWS_SSPI)
  _add_if("GSS-API"       HAVE_GSSAPI)
  _add_if("alt-svc"       NOT CURL_DISABLE_ALTSVC)
  _add_if("HSTS"          NOT CURL_DISABLE_HSTS)
  _add_if("SPNEGO"        NOT CURL_DISABLE_NEGOTIATE_AUTH AND
                          (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
  _add_if("Kerberos"      NOT CURL_DISABLE_KERBEROS_AUTH AND
                          (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
  _add_if("NTLM"          NOT (CURL_DISABLE_NTLM) AND
                          (use_curl_ntlm_core OR USE_WINDOWS_SSPI))
  _add_if("NTLM_WB"       NOT (CURL_DISABLE_NTLM) AND
                          (use_curl_ntlm_core OR USE_WINDOWS_SSPI) AND
                          NOT CURL_DISABLE_HTTP AND NTLM_WB_ENABLED)
  _add_if("TLS-SRP"       USE_TLS_SRP)
  _add_if("HTTP2"         USE_NGHTTP2)
  _add_if("HTTP3"         USE_NGTCP2 OR USE_QUICHE OR USE_OPENSSL_QUIC)
  _add_if("MultiSSL"      CURL_WITH_MULTI_SSL)
  # TODO wolfSSL only support this from v5.0.0 onwards
  _add_if("HTTPS-proxy"   SSL_ENABLED AND (USE_OPENSSL OR USE_GNUTLS
                          OR USE_SCHANNEL OR USE_RUSTLS OR USE_BEARSSL OR
                          USE_MBEDTLS OR USE_SECTRANSP))
  _add_if("unicode"       ENABLE_UNICODE)
  _add_if("threadsafe"    HAVE_ATOMIC OR
                          (USE_THREADS_POSIX AND HAVE_PTHREAD_H) OR
                          (WIN32 AND HAVE_WIN32_WINNT GREATER_EQUAL 0x600))
  _add_if("PSL"           USE_LIBPSL)
  string(REPLACE ";" " " SUPPORT_FEATURES "${_items}")
  message(STATUS "Enabled features: ${SUPPORT_FEATURES}")

  # Clear list and try to detect available protocols
  set(_items)
  _add_if("HTTP"          NOT CURL_DISABLE_HTTP)
  _add_if("IPFS"          NOT CURL_DISABLE_HTTP)
  _add_if("IPNS"          NOT CURL_DISABLE_HTTP)
  _add_if("HTTPS"         NOT CURL_DISABLE_HTTP AND SSL_ENABLED)
  _add_if("FTP"           NOT CURL_DISABLE_FTP)
  _add_if("FTPS"          NOT CURL_DISABLE_FTP AND SSL_ENABLED)
  _add_if("FILE"          NOT CURL_DISABLE_FILE)
  _add_if("TELNET"        NOT CURL_DISABLE_TELNET)
  _add_if("LDAP"          NOT CURL_DISABLE_LDAP)
  # CURL_DISABLE_LDAP implies CURL_DISABLE_LDAPS
  _add_if("LDAPS"         NOT CURL_DISABLE_LDAPS AND
                          ((USE_OPENLDAP AND SSL_ENABLED) OR
                          (NOT USE_OPENLDAP AND HAVE_LDAP_SSL)))
  _add_if("DICT"          NOT CURL_DISABLE_DICT)
  _add_if("TFTP"          NOT CURL_DISABLE_TFTP)
  _add_if("GOPHER"        NOT CURL_DISABLE_GOPHER)
  _add_if("GOPHERS"       NOT CURL_DISABLE_GOPHER AND SSL_ENABLED)
  _add_if("POP3"          NOT CURL_DISABLE_POP3)
  _add_if("POP3S"         NOT CURL_DISABLE_POP3 AND SSL_ENABLED)
  _add_if("IMAP"          NOT CURL_DISABLE_IMAP)
  _add_if("IMAPS"         NOT CURL_DISABLE_IMAP AND SSL_ENABLED)
  _add_if("SMB"           NOT CURL_DISABLE_SMB AND
                          use_curl_ntlm_core AND (SIZEOF_CURL_OFF_T GREATER 4))
  _add_if("SMBS"          NOT CURL_DISABLE_SMB AND SSL_ENABLED AND
                          use_curl_ntlm_core AND (SIZEOF_CURL_OFF_T GREATER 4))
  _add_if("SMTP"          NOT CURL_DISABLE_SMTP)
  _add_if("SMTPS"         NOT CURL_DISABLE_SMTP AND SSL_ENABLED)
  _add_if("SCP"           USE_LIBSSH2 OR USE_LIBSSH)
  _add_if("SFTP"          USE_LIBSSH2 OR USE_LIBSSH)
  _add_if("RTSP"          NOT CURL_DISABLE_RTSP)
  _add_if("RTMP"          USE_LIBRTMP)
  _add_if("MQTT"          NOT CURL_DISABLE_MQTT)
  _add_if("WS"            USE_WEBSOCKETS)
  _add_if("WSS"           USE_WEBSOCKETS)
  if(_items)
    list(SORT _items)
  endif()
  string(REPLACE ";" " " SUPPORT_PROTOCOLS "${_items}")
  message(STATUS "Enabled protocols: ${SUPPORT_PROTOCOLS}")

  # Clear list and collect SSL backends
  set(_items)
  _add_if("Schannel"         SSL_ENABLED AND USE_SCHANNEL)
  _add_if("OpenSSL"          SSL_ENABLED AND USE_OPENSSL)
  _add_if("Secure Transport" SSL_ENABLED AND USE_SECTRANSP)
  _add_if("mbedTLS"          SSL_ENABLED AND USE_MBEDTLS)
  _add_if("BearSSL"          SSL_ENABLED AND USE_BEARSSL)
  _add_if("wolfSSL"          SSL_ENABLED AND USE_WOLFSSL)
  _add_if("GnuTLS"           SSL_ENABLED AND USE_GNUTLS)

  if(_items)
    list(SORT _items)
  endif()
  string(REPLACE ";" " " SSL_BACKENDS "${_items}")
  message(STATUS "Enabled SSL backends: ${SSL_BACKENDS}")
  if(CURL_DEFAULT_SSL_BACKEND)
    message(STATUS "Default SSL backend: ${CURL_DEFAULT_SSL_BACKEND}")
  endif()

  # curl-config needs the following options to be set.
  set(CC                      "${CMAKE_C_COMPILER}")
  # TODO probably put a -D... options here?
  set(CONFIGURE_OPTIONS       "")
  set(CURLVERSION             "${CURL_VERSION}")
  set(exec_prefix             "\${prefix}")
  set(includedir              "\${prefix}/include")
  set(LDFLAGS                 "${CMAKE_SHARED_LINKER_FLAGS}")
  set(LIBCURL_LIBS            "")
  set(libdir                  "${CMAKE_INSTALL_PREFIX}/lib")

  # For processing full path libraries into -L and -l ld options,
  # the directories that go with the -L option are cached, so they
  # only get added once per such directory.
  set(_libcurl_libs_dirs)
  # To avoid getting unnecessary -L options for known system directories,
  # _libcurl_libs_dirs is seeded with them.
  foreach(_libdir ${CMAKE_SYSTEM_PREFIX_PATH})
    if(_libdir MATCHES "/$")
      set(_libdir "${_libdir}lib")
    else()
      set(_libdir "${_libdir}/lib")
    endif()
    if(IS_DIRECTORY "${_libdir}")
      list(APPEND _libcurl_libs_dirs "${_libdir}")
    endif()
    if(DEFINED CMAKE_LIBRARY_ARCHITECTURE)
      set(_libdir "${_libdir}/${CMAKE_LIBRARY_ARCHITECTURE}")
      if(IS_DIRECTORY "${_libdir}")
        list(APPEND _libcurl_libs_dirs "${_libdir}")
      endif()
    endif()
  endforeach()

  foreach(_lib ${CMAKE_C_IMPLICIT_LINK_LIBRARIES} ${CURL_LIBS})
    if(TARGET "${_lib}")
      set(_libname "${_lib}")
      get_target_property(_imported "${_libname}" IMPORTED)
      if(NOT _imported)
        # Reading the LOCATION property on non-imported target will error out.
        # Assume the user won't need this information in the .pc file.
        continue()
      endif()
      get_target_property(_lib "${_libname}" LOCATION)
      if(NOT _lib)
        message(WARNING "Bad lib in library list: ${_libname}")
        continue()
      endif()
    endif()
    if(_lib MATCHES "^-")
      set(LIBCURL_LIBS          "${LIBCURL_LIBS} ${_lib}")
    elseif(_lib MATCHES ".*/.*")
      # This gets a bit more complex, because we want to specify the
      # directory separately, and only once per directory
      string(REGEX REPLACE "^(.*)/[^/]*$" "\\1" _libdir "${_lib}")
      string(REGEX REPLACE "^.*/([^/.]*).*$" "\\1" _libname "${_lib}")
      if(_libname MATCHES "^lib")
        list(FIND _libcurl_libs_dirs "${_libdir}" _libdir_index)
        if(_libdir_index LESS 0)
          list(APPEND _libcurl_libs_dirs "${_libdir}")
          set(LIBCURL_LIBS          "${LIBCURL_LIBS} -L${_libdir}")
        endif()
        string(REGEX REPLACE "^lib" "" _libname "${_libname}")
        set(LIBCURL_LIBS          "${LIBCURL_LIBS} -l${_libname}")
      else()
        set(LIBCURL_LIBS          "${LIBCURL_LIBS} ${_lib}")
      endif()
    else()
      set(LIBCURL_LIBS          "${LIBCURL_LIBS} -l${_lib}")
    endif()
  endforeach()
  if(BUILD_SHARED_LIBS)
    set(ENABLE_SHARED         "yes")
    set(LIBCURL_NO_SHARED     "")
    set(CPPFLAG_CURL_STATICLIB "")
  else()
    set(ENABLE_SHARED         "no")
    set(LIBCURL_NO_SHARED     "${LIBCURL_LIBS}")
    set(CPPFLAG_CURL_STATICLIB "-DCURL_STATICLIB")
  endif()
  if(BUILD_STATIC_LIBS)
    set(ENABLE_STATIC         "yes")
  else()
    set(ENABLE_STATIC         "no")
  endif()
  # "a" (Linux) or "lib" (Windows)
  string(REPLACE "." "" libext "${CMAKE_STATIC_LIBRARY_SUFFIX}")
  set(prefix                  "${CMAKE_INSTALL_PREFIX}")
  # Set this to "yes" to append all libraries on which -lcurl is dependent
  set(REQUIRE_LIB_DEPS        "no")
  # SUPPORT_FEATURES
  # SUPPORT_PROTOCOLS
  set(VERSIONNUM              "${CURL_VERSION_NUM}")

  # Finally generate a "curl-config" matching this config
  # Use:
  # * ENABLE_SHARED
  # * ENABLE_STATIC
  configure_file("${CURL_SOURCE_DIR}/curl-config.in"
                "${CURL_BINARY_DIR}/curl-config" @ONLY)
  install(FILES "${CURL_BINARY_DIR}/curl-config"
          DESTINATION ${CMAKE_INSTALL_BINDIR}
          PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)

  # Finally generate a pkg-config file matching this config
  configure_file("${CURL_SOURCE_DIR}/libcurl.pc.in"
                "${CURL_BINARY_DIR}/libcurl.pc" @ONLY)
  install(FILES "${CURL_BINARY_DIR}/libcurl.pc"
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  # install headers
  install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/curl"
      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
      FILES_MATCHING PATTERN "*.h")

  include(CMakePackageConfigHelpers)
  write_basic_package_version_file(
      "${version_config}"
      VERSION ${CURL_VERSION}
      COMPATIBILITY SameMajorVersion
  )
  file(READ "${version_config}" generated_version_config)
  file(WRITE "${version_config}"
  "if(NOT PACKAGE_FIND_VERSION_RANGE AND PACKAGE_FIND_VERSION_MAJOR STREQUAL \"7\")
      # Version 8 satisfies version 7... requirements
      set(PACKAGE_FIND_VERSION_MAJOR 8)
      set(PACKAGE_FIND_VERSION_COUNT 1)
  endif()
  ${generated_version_config}"
  )

  # Use:
  # * TARGETS_EXPORT_NAME
  # * PROJECT_NAME
  configure_package_config_file(CMake/curl-config.cmake.in
          "${project_config}"
          INSTALL_DESTINATION ${CURL_INSTALL_CMAKE_DIR}
  )

  if(CURL_ENABLE_EXPORT_TARGET)
    install(
            EXPORT "${TARGETS_EXPORT_NAME}"
            NAMESPACE "${PROJECT_NAME}::"
            DESTINATION ${CURL_INSTALL_CMAKE_DIR}
    )
  endif()

  install(
          FILES ${version_config} ${project_config}
          DESTINATION ${CURL_INSTALL_CMAKE_DIR}
  )

  # Workaround for MSVS10 to avoid the Dialog Hell
  # FIXME: This could be removed with future version of CMake.
  if(MSVC_VERSION EQUAL 1600)
    set(CURL_SLN_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/CURL.sln")
    if(EXISTS "${CURL_SLN_FILENAME}")
      file(APPEND "${CURL_SLN_FILENAME}" "\n# This should be regenerated!\n")
    endif()
  endif()

  if(NOT TARGET curl_uninstall)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/CMake/cmake_uninstall.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake
        IMMEDIATE @ONLY)

    add_custom_target(curl_uninstall
        COMMAND ${CMAKE_COMMAND} -P
        ${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake)
  endif()
endif()
