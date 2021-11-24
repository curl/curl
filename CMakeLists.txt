#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
# curl/libcurl CMake script
# by Tetetest and Sukender (Benoit Neil)

# TODO:
# The output .so file lacks the soname number which we currently have within the lib/Makefile.am file
# Add full (4 or 5 libs) SSL support
# Add INSTALL target (EXTRA_DIST variables in Makefile.am may be moved to Makefile.inc so that CMake/CPack is aware of what's to include).
# Check on all possible platforms
# Test with as many configurations possible (With or without any option)
# Create scripts that help keeping the CMake build system up to date (to reduce maintenance). According to Tetetest:
#  - lists of headers that 'configure' checks for;
#  - curl-specific tests (the ones that are in m4/curl-*.m4 files);
#  - (most obvious thing:) curl version numbers.
# Add documentation subproject
#
# To check:
# (From Daniel Stenberg) The cmake build selected to run gcc with -fPIC on my box while the plain configure script did not.
# (From Daniel Stenberg) The gcc command line use neither -g nor any -O options. As a developer, I also treasure our configure scripts's --enable-debug option that sets a long range of "picky" compiler options.
cmake_minimum_required(VERSION 3.2...3.16 FATAL_ERROR)

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
set(OS "\"${CMAKE_SYSTEM_NAME}\"")

include_directories(${CURL_SOURCE_DIR}/include)

option(CURL_WERROR "Turn compiler warnings into errors" OFF)
option(PICKY_COMPILER "Enable picky compiler options" ON)
option(BUILD_CURL_EXE "Set to ON to build curl executable." ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(ENABLE_ARES "Set to ON to enable c-ares support" OFF)
if(WIN32)
  option(CURL_STATIC_CRT "Set to ON to build libcurl with static CRT on Windows (/MT)." OFF)
  option(ENABLE_INET_PTON "Set to OFF to prevent usage of inet_pton when building against modern SDKs while still requiring compatibility with older Windows versions, such as Windows XP, Windows Server 2003 etc." ON)
  option(ENABLE_UNICODE "Set to ON to use the Unicode version of the Windows API functions" OFF)
  set(CURL_TARGET_WINDOWS_VERSION "" CACHE STRING "Minimum target Windows version as hex string")
  if(CURL_TARGET_WINDOWS_VERSION)
    add_definitions(-D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION})
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_WIN32_WINNT=${CURL_TARGET_WINDOWS_VERSION}")
  elseif(ENABLE_INET_PTON)
    # _WIN32_WINNT_VISTA (0x0600)
    add_definitions(-D_WIN32_WINNT=0x0600)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_WIN32_WINNT=0x0600")
  else()
    # _WIN32_WINNT_WINXP (0x0501)
    add_definitions(-D_WIN32_WINNT=0x0501)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_WIN32_WINNT=0x0501")
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

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
  if(PICKY_COMPILER)
    foreach(_CCOPT -pedantic -Wall -W -Wpointer-arith -Wwrite-strings -Wunused -Wshadow -Winline -Wnested-externs -Wmissing-declarations -Wmissing-prototypes -Wfloat-equal -Wsign-compare -Wundef -Wendif-labels -Wstrict-prototypes -Wdeclaration-after-statement -Wstrict-aliasing=3 -Wcast-align -Wtype-limits -Wold-style-declaration -Wmissing-parameter-type -Wempty-body -Wclobbered -Wignored-qualifiers -Wconversion -Wvla -Wdouble-promotion)
      # surprisingly, CHECK_C_COMPILER_FLAG needs a new variable to store each new
      # test result in.
      string(MAKE_C_IDENTIFIER "OPT${_CCOPT}" _optvarname)
      check_c_compiler_flag(${_CCOPT} ${_optvarname})
      if(${_optvarname})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
      endif()
    endforeach()
    foreach(_CCOPT long-long multichar format-nonliteral sign-conversion system-headers pedantic-ms-format)
      # GCC only warns about unknown -Wno- options if there are also other diagnostic messages,
      # so test for the positive form instead
      string(MAKE_C_IDENTIFIER "OPT${_CCOPT}" _optvarname)
      check_c_compiler_flag("-W${_CCOPT}" ${_optvarname})
      if(${_optvarname})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-${_CCOPT}")
      endif()
    endforeach()
  endif()
endif()

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
option(CURL_DISABLE_COOKIES "disables cookies support" OFF)
mark_as_advanced(CURL_DISABLE_COOKIES)
option(CURL_DISABLE_CRYPTO_AUTH "disables cryptographic authentication" OFF)
mark_as_advanced(CURL_DISABLE_CRYPTO_AUTH)
option(CURL_DISABLE_DICT "disables DICT" OFF)
mark_as_advanced(CURL_DISABLE_DICT)
option(CURL_DISABLE_DOH "disables DNS-over-HTTPS" OFF)
mark_as_advanced(CURL_DISABLE_DOH)
option(CURL_DISABLE_FILE "disables FILE" OFF)
mark_as_advanced(CURL_DISABLE_FILE)
option(CURL_DISABLE_FTP "disables FTP" OFF)
mark_as_advanced(CURL_DISABLE_FTP)
option(CURL_DISABLE_GETOPTIONS "disables curl_easy_options API for existing options to curl_easy_setopt" OFF)
mark_as_advanced(CURL_DISABLE_GETOPTIONS)
option(CURL_DISABLE_GOPHER "disables Gopher" OFF)
mark_as_advanced(CURL_DISABLE_GOPHER)
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
    set(use_core_foundation ON)

    find_library(SYSTEMCONFIGURATION_FRAMEWORK "SystemConfiguration")
    if(NOT SYSTEMCONFIGURATION_FRAMEWORK)
      message(FATAL_ERROR "SystemConfiguration framework not found")
    endif()

    list(APPEND CURL_LIBS "-framework SystemConfiguration")
  endif()
endif()

if(USE_MANUAL)
    #nroff is currently only used when USE_MANUAL is set, so we can prevent the warning of no *NROFF if USE_MANUAL is OFF (or not defined), by not even looking for NROFF..
    curl_nroff_check()
endif()
find_package(Perl)

cmake_dependent_option(ENABLE_MANUAL "to provide the built-in manual"
    ON "NROFF_USEFUL;PERL_FOUND"
    OFF)

if(ENABLE_MANUAL)
  set(USE_MANUAL ON)
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
  set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_WINSOCKAPI_=")
  include(${CMAKE_CURRENT_SOURCE_DIR}/CMake/Platforms/WindowsCache.cmake)
endif()

if(ENABLE_THREADED_RESOLVER)
  find_package(Threads REQUIRED)
  if(WIN32)
    set(USE_THREADS_WIN32 ON)
  else()
    set(USE_THREADS_POSIX ${CMAKE_USE_PTHREADS_INIT})
    set(HAVE_PTHREAD_H ${CMAKE_USE_PTHREADS_INIT})
  endif()
  set(CURL_LIBS ${CURL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
endif()

# Check for all needed libraries
check_library_exists_concat("${CMAKE_DL_LIBS}" dlopen HAVE_LIBDL)
check_library_exists_concat("socket" connect      HAVE_LIBSOCKET)
check_library_exists("c" gethostbyname "" NOT_NEED_LIBNSL)

# Yellowtab Zeta needs different libraries than BeOS 5.
if(BEOS)
  set(NOT_NEED_LIBNSL 1)
  check_library_exists_concat("bind" gethostbyname HAVE_LIBBIND)
  check_library_exists_concat("bnetapi" closesocket HAVE_LIBBNETAPI)
endif()

if(NOT NOT_NEED_LIBNSL)
  check_library_exists_concat("nsl"    gethostbyname  HAVE_LIBNSL)
endif()

check_function_exists(gethostname HAVE_GETHOSTNAME)

if(WIN32)
  check_library_exists_concat("ws2_32" getch        HAVE_LIBWS2_32)
  check_library_exists_concat("winmm"  getch        HAVE_LIBWINMM)
endif()

# This check below for use of deprecated symbols is only temporary and is to
# be removed again after a year's service. Remove after November 25, 2022.
set(CURL_RECONFIG_REQUIRED 0)
foreach(_LIB GSSAPI OPENLDAP LIBSSH LIBSSH2 BEARSSL MBEDTLS NSS OPENSSL
        SCHANNEL SECTRANSP WOLFSSL)
  if(CMAKE_USE_${_LIB})
    set(CURL_RECONFIG_REQUIRED 1)
    message(SEND_ERROR "The option CMAKE_USE_${_LIB} was renamed to CURL_USE_${_LIB}.")
  endif()
endforeach()
if(CMAKE_USE_WINSSL)
  set(CURL_RECONFIG_REQUIRED 1)
  message(SEND_ERROR "The option CMAKE_USE_WINSSL was renamed to CURL_USE_SCHANNEL.")
endif()
if(CURL_RECONFIG_REQUIRED)
  message(FATAL_ERROR "Reconfig required")
endif()

# check SSL libraries
# TODO support GnuTLS
option(CURL_ENABLE_SSL "Enable SSL support" ON)

if(APPLE)
  cmake_dependent_option(CURL_USE_SECTRANSP "enable Apple OS native SSL/TLS" OFF CURL_ENABLE_SSL OFF)
endif()
if(WIN32)
  cmake_dependent_option(CURL_USE_SCHANNEL "enable Windows native SSL/TLS" OFF CURL_ENABLE_SSL OFF)
  cmake_dependent_option(CURL_WINDOWS_SSPI "Use windows libraries to allow NTLM authentication without openssl" ON
    CURL_USE_SCHANNEL OFF)
endif()
cmake_dependent_option(CURL_USE_MBEDTLS "Enable mbedTLS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_BEARSSL "Enable BearSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_NSS "Enable NSS for SSL/TLS" OFF CURL_ENABLE_SSL OFF)
cmake_dependent_option(CURL_USE_WOLFSSL "enable wolfSSL for SSL/TLS" OFF CURL_ENABLE_SSL OFF)

set(openssl_default ON)
if(WIN32 OR CURL_USE_SECTRANSP OR CURL_USE_SCHANNEL OR CURL_USE_MBEDTLS OR CURL_USE_NSS OR CURL_USE_WOLFSSL)
  set(openssl_default OFF)
endif()
cmake_dependent_option(CURL_USE_OPENSSL "Use OpenSSL code. Experimental" ${openssl_default} CURL_ENABLE_SSL OFF)
option(CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG "Disable automatic loading of OpenSSL configuration" OFF)

count_true(enabled_ssl_options_count
  CURL_USE_SCHANNEL
  CURL_USE_SECTRANSP
  CURL_USE_OPENSSL
  CURL_USE_MBEDTLS
  CURL_USE_BEARSSL
  CURL_USE_NSS
  CURL_USE_WOLFSSL
)
if(enabled_ssl_options_count GREATER "1")
  set(CURL_WITH_MULTI_SSL ON)
endif()

if(CURL_USE_SCHANNEL)
  set(SSL_ENABLED ON)
  set(USE_SCHANNEL ON) # Windows native SSL/TLS support
  set(USE_WINDOWS_SSPI ON) # CURL_USE_SCHANNEL implies CURL_WINDOWS_SSPI
endif()
if(CURL_WINDOWS_SSPI)
  set(USE_WINDOWS_SSPI ON)
  set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -DSECURITY_WIN32")
endif()

if(CURL_USE_SECTRANSP)
  set(use_core_foundation ON)

  find_library(SECURITY_FRAMEWORK "Security")
  if(NOT SECURITY_FRAMEWORK)
     message(FATAL_ERROR "Security framework not found")
  endif()

  set(SSL_ENABLED ON)
  set(USE_SECTRANSP ON)
  list(APPEND CURL_LIBS "-framework Security")
endif()

if(use_core_foundation)
  find_library(COREFOUNDATION_FRAMEWORK "CoreFoundation")
  if(NOT COREFOUNDATION_FRAMEWORK)
      message(FATAL_ERROR "CoreFoundation framework not found")
  endif()

  list(APPEND CURL_LIBS "-framework CoreFoundation")
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

  set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
  check_include_file("openssl/crypto.h" HAVE_OPENSSL_CRYPTO_H)
  check_include_file("openssl/err.h"    HAVE_OPENSSL_ERR_H)
  check_include_file("openssl/pem.h"    HAVE_OPENSSL_PEM_H)
  check_include_file("openssl/rsa.h"    HAVE_OPENSSL_RSA_H)
  check_include_file("openssl/ssl.h"    HAVE_OPENSSL_SSL_H)
  check_include_file("openssl/x509.h"   HAVE_OPENSSL_X509_H)
  check_include_file("openssl/rand.h"   HAVE_OPENSSL_RAND_H)
  check_symbol_exists(RAND_status "${CURL_INCLUDES}" HAVE_RAND_STATUS)
  check_symbol_exists(RAND_screen "${CURL_INCLUDES}" HAVE_RAND_SCREEN)
  check_symbol_exists(RAND_egd    "${CURL_INCLUDES}" HAVE_RAND_EGD)

  add_definitions(-DOPENSSL_SUPPRESS_DEPRECATED)
endif()

if(CURL_USE_MBEDTLS)
  find_package(MbedTLS REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_MBEDTLS ON)
  list(APPEND CURL_LIBS ${MBEDTLS_LIBRARIES})
  include_directories(${MBEDTLS_INCLUDE_DIRS})
endif()

if(CURL_USE_BEARSSL)
  find_package(BearSSL REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_BEARSSL ON)
  list(APPEND CURL_LIBS ${BEARSSL_LIBRARY})
  include_directories(${BEARSSL_INCLUDE_DIRS})
endif()

if(CURL_USE_WOLFSSL)
  find_package(WolfSSL REQUIRED)
  set(SSL_ENABLED ON)
  set(USE_WOLFSSL ON)
  list(APPEND CURL_LIBS ${WolfSSL_LIBRARIES})
  include_directories(${WolfSSL_INCLUDE_DIRS})
endif()

if(CURL_USE_NSS)
  find_package(NSS REQUIRED)
  include_directories(${NSS_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NSS_LIBRARIES})
  set(SSL_ENABLED ON)
  set(USE_NSS ON)
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES ${NSS_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${NSS_LIBRARIES})
  check_symbol_exists(PK11_CreateManagedGenericObject "pk11pub.h" HAVE_PK11_CREATEMANAGEDGENERICOBJECT)
  cmake_pop_check_state()
endif()

option(USE_NGHTTP2 "Use Nghttp2 library" OFF)
if(USE_NGHTTP2)
  find_package(NGHTTP2 REQUIRED)
  include_directories(${NGHTTP2_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${NGHTTP2_LIBRARIES})
endif()

function(CheckQuicSupportInOpenSSL)
  # Be sure that the OpenSSL library actually supports QUIC.
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES   "${OPENSSL_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_LIBRARIES  "${OPENSSL_LIBRARIES}")
  check_symbol_exists(SSL_CTX_set_quic_method "openssl/ssl.h" HAVE_SSL_CTX_SET_QUIC_METHOD)
  if(NOT HAVE_SSL_CTX_SET_QUIC_METHOD)
    message(FATAL_ERROR "QUIC support is missing in OpenSSL/boringssl. Try setting -DOPENSSL_ROOT_DIR")
  endif()
  cmake_pop_check_state()
endfunction()

option(USE_NGTCP2 "Use ngtcp2 and nghttp3 libraries for HTTP/3 support" OFF)
if(USE_NGTCP2)
  if(USE_OPENSSL)
    find_package(NGTCP2 REQUIRED OpenSSL)
    CheckQuicSupportInOpenSSL()
  elseif(USE_GNUTLS)
    # TODO add GnuTLS support as vtls library.
    find_package(NGTCP2 REQUIRED GnuTLS)
  else()
    message(FATAL_ERROR "ngtcp2 requires OpenSSL or GnuTLS")
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
  CheckQuicSupportInOpenSSL()
  set(USE_QUICHE ON)
  include_directories(${QUICHE_INCLUDE_DIRS})
  list(APPEND CURL_LIBS ${QUICHE_LIBRARIES})
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES   "${QUICHE_INCLUDE_DIRS}")
  set(CMAKE_REQUIRED_LIBRARIES  "${QUICHE_LIBRARIES}")
  check_symbol_exists(quiche_conn_set_qlog_fd "quiche.h" HAVE_QUICHE_CONN_SET_QLOG_FD)
  cmake_pop_check_state()
endif()

if(NOT CURL_DISABLE_LDAP)
  if(WIN32)
    option(USE_WIN32_LDAP "Use Windows LDAP implementation" ON)
    if(USE_WIN32_LDAP)
      check_library_exists_concat("wldap32" cldap_open HAVE_WLDAP32)
      if(NOT HAVE_WLDAP32)
        set(USE_WIN32_LDAP OFF)
      endif()
    endif()
  endif()

  option(CURL_USE_OPENLDAP "Use OpenLDAP code." OFF)
  mark_as_advanced(CURL_USE_OPENLDAP)
  set(CMAKE_LDAP_LIB "ldap" CACHE STRING "Name or full path to ldap library")
  set(CMAKE_LBER_LIB "lber" CACHE STRING "Name or full path to lber library")

  if(CURL_USE_OPENLDAP AND USE_WIN32_LDAP)
    message(FATAL_ERROR "Cannot use USE_WIN32_LDAP and CURL_USE_OPENLDAP at the same time")
  endif()

  # Now that we know, we're not using windows LDAP...
  if(USE_WIN32_LDAP)
    check_include_file_concat("winldap.h" HAVE_WINLDAP_H)
    check_include_file_concat("winber.h"  HAVE_WINBER_H)
  else()
    # Check for LDAP
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    check_library_exists_concat(${CMAKE_LDAP_LIB} ldap_init HAVE_LIBLDAP)
    check_library_exists_concat(${CMAKE_LBER_LIB} ber_init HAVE_LIBLBER)

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
      if(CURL_USE_OPENLDAP)
        set(USE_OPENLDAP ON)
      endif()
      if(CMAKE_LDAP_INCLUDE_DIR)
        include_directories(${CMAKE_LDAP_INCLUDE_DIR})
      endif()
      set(NEED_LBER_H ON)
      set(_HEADER_LIST)
      if(HAVE_WINDOWS_H)
        list(APPEND _HEADER_LIST "windows.h")
      endif()
      if(HAVE_SYS_TYPES_H)
        list(APPEND _HEADER_LIST "sys/types.h")
      endif()
      list(APPEND _HEADER_LIST "ldap.h")

      set(_SRC_STRING "")
      foreach(_HEADER ${_HEADER_LIST})
        set(_INCLUDE_STRING "${_INCLUDE_STRING}#include <${_HEADER}>\n")
      endforeach()

      set(_SRC_STRING
        "
        ${_INCLUDE_STRING}
        int main(int argc, char ** argv)
        {
          BerValue *bvp = NULL;
          BerElement *bep = ber_init(bvp);
          ber_free(bep, 1);
          return 0;
        }"
      )
      set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -DLDAP_DEPRECATED=1")
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_LDAP_LIB})
      if(HAVE_LIBLBER)
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_LBER_LIB})
      endif()
      check_c_source_compiles("${_SRC_STRING}" NOT_NEED_LBER_H)
      unset(CMAKE_REQUIRED_LIBRARIES)

      if(NOT_NEED_LBER_H)
        set(NEED_LBER_H OFF)
      else()
        set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -DNEED_LBER_H")
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

if(NOT CURL_DISABLE_LDAPS)
  check_include_file_concat("ldap_ssl.h" HAVE_LDAP_SSL_H)
  check_include_file_concat("ldapssl.h"  HAVE_LDAPSSL_H)
endif()

# Check for idn
option(USE_LIBIDN2 "Use libidn2 for IDN support" ON)
set(HAVE_LIBIDN2 OFF)
if(USE_LIBIDN2)
  check_library_exists_concat("idn2" idn2_lookup_ul HAVE_LIBIDN2)
endif()

if(WIN32)
  option(USE_WIN32_IDN "Use WinIDN for IDN support" OFF)
  if(USE_WIN32_IDN)
    list(APPEND CURL_LIBS "Normaliz")
    set(WANT_IDN_PROTOTYPES ON)
  endif()
endif()

# Check for symbol dlopen (same as HAVE_LIBDL)
check_library_exists("${CURL_LIBS}" dlopen "" HAVE_DLOPEN)

set(HAVE_LIBZ OFF)
set(HAVE_ZLIB_H OFF)
set(USE_ZLIB OFF)
optional_dependency(ZLIB)
if(ZLIB_FOUND)
  set(HAVE_ZLIB_H ON)
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
  find_package(Brotli QUIET)
  if(BROTLI_FOUND)
    set(HAVE_BROTLI ON)
    list(APPEND CURL_LIBS ${BROTLI_LIBRARIES})
    include_directories(${BROTLI_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_INCLUDES ${BROTLI_INCLUDE_DIRS})
  endif()
endif()

option(CURL_ZSTD "Set to ON to enable building curl with zstd support." OFF)
set(HAVE_ZSTD OFF)
if(CURL_ZSTD)
  find_package(Zstd REQUIRED)
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES ${Zstd_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${Zstd_LIBRARIES})
  check_symbol_exists(ZSTD_createDStream "zstd.h" HAVE_ZSTD_CREATEDSTREAM)
  cmake_pop_check_state()
  if(Zstd_FOUND AND HAVE_ZSTD_CREATEDSTREAM)
    set(HAVE_ZSTD ON)
    list(APPEND CURL_LIBS ${Zstd_LIBRARIES})
    include_directories(${Zstd_INCLUDE_DIRS})
  endif()
endif()

#libSSH2
option(CURL_USE_LIBSSH2 "Use libSSH2" ON)
mark_as_advanced(CURL_USE_LIBSSH2)
set(USE_LIBSSH2 OFF)
set(HAVE_LIBSSH2 OFF)
set(HAVE_LIBSSH2_H OFF)

if(CURL_USE_LIBSSH2)
  find_package(LibSSH2)
  if(LIBSSH2_FOUND)
    list(APPEND CURL_LIBS ${LIBSSH2_LIBRARY})
    set(CMAKE_REQUIRED_LIBRARIES ${LIBSSH2_LIBRARY})
    list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBSSH2_INCLUDE_DIR}")
    include_directories("${LIBSSH2_INCLUDE_DIR}")
    set(HAVE_LIBSSH2 ON)
    set(USE_LIBSSH2 ON)

    # find_package has already found the headers
    set(HAVE_LIBSSH2_H ON)
    set(CURL_INCLUDES ${CURL_INCLUDES} "${LIBSSH2_INCLUDE_DIR}/libssh2.h")
    set(CURL_TEST_DEFINES "${CURL_TEST_DEFINES} -DHAVE_LIBSSH2_H")
    unset(CMAKE_REQUIRED_LIBRARIES)
  endif()
endif()

# libssh
option(CURL_USE_LIBSSH "Use libSSH" OFF)
mark_as_advanced(CURL_USE_LIBSSH)
if(NOT HAVE_LIBSSH2 AND CURL_USE_LIBSSH)
  find_package(libssh CONFIG)
  if(libssh_FOUND)
    message(STATUS "Found libssh ${libssh_VERSION}")
    # Use imported target for include and library paths.
    list(APPEND CURL_LIBS ssh)
    set(USE_LIBSSH ON)
    set(HAVE_LIBSSH_LIBSSH_H 1)
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

    if(GSS_FLAVOUR STREQUAL "Heimdal")
      set(HAVE_GSSHEIMDAL ON)
    else() # MIT
      set(HAVE_GSSMIT ON)
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

      set(CMAKE_REQUIRED_FLAGS "${_COMPILER_FLAGS_STR} ${_LINKER_FLAGS_STR}")
      set(CMAKE_REQUIRED_LIBRARIES ${GSS_LIBRARIES})
      check_symbol_exists("GSS_C_NT_HOSTBASED_SERVICE" ${_INCLUDE_LIST} HAVE_GSS_C_NT_HOSTBASED_SERVICE)
      if(NOT HAVE_GSS_C_NT_HOSTBASED_SERVICE)
        set(HAVE_OLD_GSSMIT ON)
      endif()
      unset(CMAKE_REQUIRED_LIBRARIES)

    endif()

    include_directories(${GSS_INCLUDE_DIR})
    link_directories(${GSS_LINK_DIRECTORIES})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GSS_COMPILER_FLAGS}")
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
  set(CURL_CA_BUNDLE_AUTODETECT TRUE)
else()
  set(CURL_CA_BUNDLE_SET TRUE)
endif()

if("${CURL_CA_PATH}" STREQUAL "")
  message(FATAL_ERROR "Invalid value of CURL_CA_PATH. Use 'none', 'auto' or directory path.")
elseif("${CURL_CA_PATH}" STREQUAL "none")
  unset(CURL_CA_PATH CACHE)
elseif("${CURL_CA_PATH}" STREQUAL "auto")
  unset(CURL_CA_PATH CACHE)
  if(NOT USE_NSS)
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

if(CURL_CA_PATH_SET AND NOT USE_OPENSSL AND NOT USE_MBEDTLS)
  message(STATUS
          "CA path only supported by OpenSSL, GnuTLS or mbed TLS. "
          "Set CURL_CA_PATH=none or enable one of those TLS backends.")
endif()

# Check for header files
if(NOT UNIX)
  check_include_file_concat("windows.h"      HAVE_WINDOWS_H)
  check_include_file_concat("ws2tcpip.h"     HAVE_WS2TCPIP_H)
  check_include_file_concat("winsock2.h"     HAVE_WINSOCK2_H)
  check_include_file_concat("wincrypt.h"     HAVE_WINCRYPT_H)
endif()

check_include_file_concat("stdio.h"          HAVE_STDIO_H)
check_include_file_concat("inttypes.h"       HAVE_INTTYPES_H)
check_include_file_concat("sys/filio.h"      HAVE_SYS_FILIO_H)
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
check_include_file_concat("sys/uio.h"        HAVE_SYS_UIO_H)
check_include_file_concat("sys/un.h"         HAVE_SYS_UN_H)
check_include_file_concat("sys/utime.h"      HAVE_SYS_UTIME_H)
check_include_file_concat("sys/xattr.h"      HAVE_SYS_XATTR_H)
check_include_file_concat("alloca.h"         HAVE_ALLOCA_H)
check_include_file_concat("arpa/inet.h"      HAVE_ARPA_INET_H)
check_include_file_concat("arpa/tftp.h"      HAVE_ARPA_TFTP_H)
check_include_file_concat("assert.h"         HAVE_ASSERT_H)
check_include_file_concat("errno.h"          HAVE_ERRNO_H)
check_include_file_concat("fcntl.h"          HAVE_FCNTL_H)
check_include_file_concat("idn2.h"           HAVE_IDN2_H)
check_include_file_concat("ifaddrs.h"        HAVE_IFADDRS_H)
check_include_file_concat("io.h"             HAVE_IO_H)
check_include_file_concat("krb.h"            HAVE_KRB_H)
check_include_file_concat("libgen.h"         HAVE_LIBGEN_H)
check_include_file_concat("locale.h"         HAVE_LOCALE_H)
check_include_file_concat("net/if.h"         HAVE_NET_IF_H)
check_include_file_concat("netdb.h"          HAVE_NETDB_H)
check_include_file_concat("netinet/in.h"     HAVE_NETINET_IN_H)
check_include_file_concat("netinet/tcp.h"    HAVE_NETINET_TCP_H)
check_include_file("linux/tcp.h"      HAVE_LINUX_TCP_H)

check_include_file_concat("pem.h"            HAVE_PEM_H)
check_include_file_concat("poll.h"           HAVE_POLL_H)
check_include_file_concat("pwd.h"            HAVE_PWD_H)
check_include_file_concat("setjmp.h"         HAVE_SETJMP_H)
check_include_file_concat("signal.h"         HAVE_SIGNAL_H)
check_include_file_concat("ssl.h"            HAVE_SSL_H)
check_include_file_concat("stdbool.h"        HAVE_STDBOOL_H)
check_include_file_concat("stdint.h"         HAVE_STDINT_H)
check_include_file_concat("stdio.h"          HAVE_STDIO_H)
check_include_file_concat("stdlib.h"         HAVE_STDLIB_H)
check_include_file_concat("string.h"         HAVE_STRING_H)
check_include_file_concat("strings.h"        HAVE_STRINGS_H)
check_include_file_concat("stropts.h"        HAVE_STROPTS_H)
check_include_file_concat("termio.h"         HAVE_TERMIO_H)
check_include_file_concat("termios.h"        HAVE_TERMIOS_H)
check_include_file_concat("time.h"           HAVE_TIME_H)
check_include_file_concat("unistd.h"         HAVE_UNISTD_H)
check_include_file_concat("utime.h"          HAVE_UTIME_H)
check_include_file_concat("x509.h"           HAVE_X509_H)

check_include_file_concat("process.h"        HAVE_PROCESS_H)
check_include_file_concat("stddef.h"         HAVE_STDDEF_H)
check_include_file_concat("dlfcn.h"          HAVE_DLFCN_H)
check_include_file_concat("malloc.h"         HAVE_MALLOC_H)
check_include_file_concat("memory.h"         HAVE_MEMORY_H)
check_include_file_concat("netinet/if_ether.h" HAVE_NETINET_IF_ETHER_H)
check_include_file_concat("stdint.h"        HAVE_STDINT_H)
check_include_file_concat("sockio.h"        HAVE_SOCKIO_H)
check_include_file_concat("sys/utsname.h"   HAVE_SYS_UTSNAME_H)

check_type_size(size_t  SIZEOF_SIZE_T)
check_type_size(ssize_t  SIZEOF_SSIZE_T)
check_type_size("long long"  SIZEOF_LONG_LONG)
check_type_size("long"  SIZEOF_LONG)
check_type_size("short"  SIZEOF_SHORT)
check_type_size("int"  SIZEOF_INT)
check_type_size("__int64"  SIZEOF___INT64)
check_type_size("long double"  SIZEOF_LONG_DOUBLE)
check_type_size("time_t"  SIZEOF_TIME_T)
if(NOT HAVE_SIZEOF_SSIZE_T)
  if(SIZEOF_LONG EQUAL SIZEOF_SIZE_T)
    set(ssize_t long)
  endif()
  if(NOT ssize_t AND SIZEOF___INT64 EQUAL SIZEOF_SIZE_T)
    set(ssize_t __int64)
  endif()
endif()
# off_t is sized later, after the HAVE_FILE_OFFSET_BITS test

if(HAVE_SIZEOF_LONG_LONG)
  set(HAVE_LONGLONG 1)
  set(HAVE_LL 1)
endif()

find_file(RANDOM_FILE urandom /dev)
mark_as_advanced(RANDOM_FILE)

# Check for some functions that are used
if(HAVE_LIBWS2_32)
  set(CMAKE_REQUIRED_LIBRARIES ws2_32)
elseif(HAVE_LIBSOCKET)
  set(CMAKE_REQUIRED_LIBRARIES socket)
endif()

check_symbol_exists(basename      "${CURL_INCLUDES}" HAVE_BASENAME)
check_symbol_exists(socket        "${CURL_INCLUDES}" HAVE_SOCKET)
check_symbol_exists(select        "${CURL_INCLUDES}" HAVE_SELECT)
check_symbol_exists(poll          "${CURL_INCLUDES}" HAVE_POLL)
check_symbol_exists(strdup        "${CURL_INCLUDES}" HAVE_STRDUP)
check_symbol_exists(strstr        "${CURL_INCLUDES}" HAVE_STRSTR)
check_symbol_exists(strtok_r      "${CURL_INCLUDES}" HAVE_STRTOK_R)
check_symbol_exists(strftime      "${CURL_INCLUDES}" HAVE_STRFTIME)
check_symbol_exists(uname         "${CURL_INCLUDES}" HAVE_UNAME)
check_symbol_exists(strcasecmp    "${CURL_INCLUDES}" HAVE_STRCASECMP)
check_symbol_exists(stricmp       "${CURL_INCLUDES}" HAVE_STRICMP)
check_symbol_exists(strcmpi       "${CURL_INCLUDES}" HAVE_STRCMPI)
check_symbol_exists(strncmpi      "${CURL_INCLUDES}" HAVE_STRNCMPI)
check_symbol_exists(alarm         "${CURL_INCLUDES}" HAVE_ALARM)
if(NOT HAVE_STRNCMPI)
  set(HAVE_STRCMPI)
endif()
check_symbol_exists(getppid       "${CURL_INCLUDES}" HAVE_GETPPID)
check_symbol_exists(utimes        "${CURL_INCLUDES}" HAVE_UTIMES)

check_symbol_exists(gettimeofday  "${CURL_INCLUDES}" HAVE_GETTIMEOFDAY)
check_symbol_exists(inet_addr     "${CURL_INCLUDES}" HAVE_INET_ADDR)
check_symbol_exists(closesocket   "${CURL_INCLUDES}" HAVE_CLOSESOCKET)
check_symbol_exists(sigsetjmp     "${CURL_INCLUDES}" HAVE_SIGSETJMP)
check_symbol_exists(getpass_r     "${CURL_INCLUDES}" HAVE_GETPASS_R)
check_symbol_exists(getpwuid      "${CURL_INCLUDES}" HAVE_GETPWUID)
check_symbol_exists(getpwuid_r    "${CURL_INCLUDES}" HAVE_GETPWUID_R)
check_symbol_exists(geteuid       "${CURL_INCLUDES}" HAVE_GETEUID)
check_symbol_exists(usleep        "${CURL_INCLUDES}" HAVE_USLEEP)
check_symbol_exists(utime         "${CURL_INCLUDES}" HAVE_UTIME)
check_symbol_exists(gmtime_r      "${CURL_INCLUDES}" HAVE_GMTIME_R)
check_symbol_exists(localtime_r   "${CURL_INCLUDES}" HAVE_LOCALTIME_R)

check_symbol_exists(gethostbyname   "${CURL_INCLUDES}" HAVE_GETHOSTBYNAME)
check_symbol_exists(gethostbyname_r "${CURL_INCLUDES}" HAVE_GETHOSTBYNAME_R)

check_symbol_exists(signal        "${CURL_INCLUDES}" HAVE_SIGNAL_FUNC)
check_symbol_exists(SIGALRM       "${CURL_INCLUDES}" HAVE_SIGNAL_MACRO)
if(HAVE_SIGNAL_FUNC AND HAVE_SIGNAL_MACRO)
  set(HAVE_SIGNAL 1)
endif()
check_symbol_exists(uname          "${CURL_INCLUDES}" HAVE_UNAME)
check_symbol_exists(strtoll        "${CURL_INCLUDES}" HAVE_STRTOLL)
check_symbol_exists(_strtoi64      "${CURL_INCLUDES}" HAVE__STRTOI64)
check_symbol_exists(strerror_r     "${CURL_INCLUDES}" HAVE_STRERROR_R)
check_symbol_exists(siginterrupt   "${CURL_INCLUDES}" HAVE_SIGINTERRUPT)
check_symbol_exists(getaddrinfo    "${CURL_INCLUDES}" HAVE_GETADDRINFO)
check_symbol_exists(freeaddrinfo   "${CURL_INCLUDES}" HAVE_FREEADDRINFO)
check_symbol_exists(pipe           "${CURL_INCLUDES}" HAVE_PIPE)
check_symbol_exists(ftruncate      "${CURL_INCLUDES}" HAVE_FTRUNCATE)
check_symbol_exists(getprotobyname "${CURL_INCLUDES}" HAVE_GETPROTOBYNAME)
check_symbol_exists(getpeername    "${CURL_INCLUDES}" HAVE_GETPEERNAME)
check_symbol_exists(getsockname    "${CURL_INCLUDES}" HAVE_GETSOCKNAME)
check_symbol_exists(if_nametoindex "${CURL_INCLUDES}" HAVE_IF_NAMETOINDEX)
check_symbol_exists(getrlimit      "${CURL_INCLUDES}" HAVE_GETRLIMIT)
check_symbol_exists(setlocale      "${CURL_INCLUDES}" HAVE_SETLOCALE)
check_symbol_exists(setmode        "${CURL_INCLUDES}" HAVE_SETMODE)
check_symbol_exists(setrlimit      "${CURL_INCLUDES}" HAVE_SETRLIMIT)
check_symbol_exists(fcntl          "${CURL_INCLUDES}" HAVE_FCNTL)
check_symbol_exists(ioctl          "${CURL_INCLUDES}" HAVE_IOCTL)
check_symbol_exists(setsockopt     "${CURL_INCLUDES}" HAVE_SETSOCKOPT)
check_function_exists(mach_absolute_time HAVE_MACH_ABSOLUTE_TIME)
check_symbol_exists(inet_pton      "${CURL_INCLUDES}" HAVE_INET_PTON)

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

set(CMAKE_EXTRA_INCLUDE_FILES   "ws2def.h")
check_type_size("ADDRESS_FAMILY"    SIZEOF_ADDRESS_FAMILY)
set(HAVE_ADDRESS_FAMILY         ${HAVE_SIZEOF_ADDRESS_FAMILY})
set(CMAKE_EXTRA_INCLUDE_FILES   "")

# sigaction and sigsetjmp are special. Use special mechanism for
# detecting those, but only if previous attempt failed.
if(HAVE_SIGNAL_H)
  check_symbol_exists(sigaction "signal.h" HAVE_SIGACTION)
endif()

if(NOT HAVE_SIGSETJMP)
  if(HAVE_SETJMP_H)
    check_symbol_exists(sigsetjmp "setjmp.h" HAVE_MACRO_SIGSETJMP)
    if(HAVE_MACRO_SIGSETJMP)
      set(HAVE_SIGSETJMP 1)
    endif()
  endif()
endif()

# If there is no stricmp(), do not allow LDAP to parse URLs
if(NOT HAVE_STRICMP)
  set(HAVE_LDAP_URL_PARSE 1)
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
    HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
    TIME_WITH_SYS_TIME
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
    HAVE_GETADDRINFO
    HAVE_FILE_OFFSET_BITS
    HAVE_VARIADIC_MACROS_C99
    HAVE_VARIADIC_MACROS_GCC
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
set(CMAKE_EXTRA_INCLUDE_FILES "")

set(CMAKE_REQUIRED_FLAGS)

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

# Check clock_gettime(CLOCK_MONOTONIC, x) support
curl_internal_test(HAVE_CLOCK_GETTIME_MONOTONIC)

# Check compiler support of __builtin_available()
curl_internal_test(HAVE_BUILTIN_AVAILABLE)

# Some other minor tests

if(NOT HAVE_IN_ADDR_T)
  set(in_addr_t "unsigned long")
endif()

# Fix libz / zlib.h

if(NOT CURL_SPECIAL_LIBZ)
  if(NOT HAVE_LIBZ)
    set(HAVE_ZLIB_H 0)
  endif()

  if(NOT HAVE_ZLIB_H)
    set(HAVE_LIBZ 0)
  endif()
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

# TODO test which of these headers are required
if(WIN32)
  set(CURL_PULL_WS2TCPIP_H ${HAVE_WS2TCPIP_H})
else()
  set(CURL_PULL_SYS_TYPES_H ${HAVE_SYS_TYPES_H})
  set(CURL_PULL_SYS_SOCKET_H ${HAVE_SYS_SOCKET_H})
  set(CURL_PULL_SYS_POLL_H ${HAVE_SYS_POLL_H})
endif()
set(CURL_PULL_STDINT_H ${HAVE_STDINT_H})
set(CURL_PULL_INTTYPES_H ${HAVE_INTTYPES_H})

include(CMake/OtherTests.cmake)

add_definitions(-DHAVE_CONFIG_H)

# For Windows, all compilers used by CMake should support large files
if(WIN32)
  set(USE_WIN32_LARGE_FILES ON)

  # Use the manifest embedded in the Windows Resource
  set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -DCURL_EMBED_MANIFEST")

  # Check if crypto functions in wincrypt.h are actually available
  if(HAVE_WINCRYPT_H)
    check_symbol_exists(CryptAcquireContext "${CURL_INCLUDES}" USE_WINCRYPT)
  endif()
  if(USE_WINCRYPT)
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

if(USE_MANUAL)
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

# Helper to populate a list (_items) with a label when conditions (the remaining
# args) are satisfied
macro(_add_if label)
  # needs to be a macro to allow this indirection
  if(${ARGN})
    set(_items ${_items} "${label}")
  endif()
endmacro()

# NTLM support requires crypto function adaptions from various SSL libs
# TODO alternative SSL libs tests for SSP1, GNUTLS, NSS
if(NOT (CURL_DISABLE_CRYPTO_AUTH OR CURL_DISABLE_NTLM) AND
    (USE_OPENSSL OR USE_MBEDTLS OR USE_DARWINSSL OR USE_WIN32_CRYPTO))
  set(use_curl_ntlm_core ON)
endif()

# Clear list and try to detect available features
set(_items)
_add_if("SSL"           SSL_ENABLED)
_add_if("IPv6"          ENABLE_IPV6)
_add_if("unixsockets"   USE_UNIX_SOCKETS)
_add_if("libz"          HAVE_LIBZ)
_add_if("brotli"        HAVE_BROTLI)
_add_if("zstd"          HAVE_ZSTD)
_add_if("AsynchDNS"     USE_ARES OR USE_THREADS_POSIX OR USE_THREADS_WIN32)
_add_if("IDN"           HAVE_LIBIDN2 OR USE_WIN32_IDN)
_add_if("Largefile"     (SIZEOF_CURL_OFF_T GREATER 4) AND
                        ((SIZEOF_OFF_T GREATER 4) OR USE_WIN32_LARGE_FILES))
# TODO SSP1 (Schannel) check is missing
_add_if("SSPI"          USE_WINDOWS_SSPI)
_add_if("GSS-API"       HAVE_GSSAPI)
_add_if("alt-svc"       NOT CURL_DISABLE_ALTSVC)
_add_if("HSTS"          NOT CURL_DISABLE_HSTS)
# TODO SSP1 missing for SPNEGO
_add_if("SPNEGO"        NOT CURL_DISABLE_CRYPTO_AUTH AND
                        (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
_add_if("Kerberos"      NOT CURL_DISABLE_CRYPTO_AUTH AND
                        (HAVE_GSSAPI OR USE_WINDOWS_SSPI))
# NTLM support requires crypto function adaptions from various SSL libs
# TODO alternative SSL libs tests for SSP1, GNUTLS, NSS
_add_if("NTLM"          NOT (CURL_DISABLE_CRYPTO_AUTH OR CURL_DISABLE_NTLM) AND
                        (use_curl_ntlm_core OR USE_WINDOWS_SSPI))
# TODO missing option (autoconf: --enable-ntlm-wb)
_add_if("NTLM_WB"       NOT (CURL_DISABLE_CRYPTO_AUTH OR CURL_DISABLE_NTLM) AND
                        (use_curl_ntlm_core OR USE_WINDOWS_SSPI) AND
                        NOT CURL_DISABLE_HTTP AND NTLM_WB_ENABLED)
# TODO missing option (--enable-tls-srp), depends on GNUTLS_SRP/OPENSSL_SRP
_add_if("TLS-SRP"       USE_TLS_SRP)
# TODO option --with-nghttp2 tests for nghttp2 lib and nghttp2/nghttp2.h header
_add_if("HTTP2"         USE_NGHTTP2)
_add_if("HTTP3"         USE_NGTCP2 OR USE_QUICHE)
_add_if("MultiSSL"      CURL_WITH_MULTI_SSL)
_add_if("HTTPS-proxy"   SSL_ENABLED AND (USE_OPENSSL OR USE_GNUTLS OR USE_NSS))
_add_if("unicode"       ENABLE_UNICODE)
string(REPLACE ";" " " SUPPORT_FEATURES "${_items}")
message(STATUS "Enabled features: ${SUPPORT_FEATURES}")

# Clear list and try to detect available protocols
set(_items)
_add_if("HTTP"          NOT CURL_DISABLE_HTTP)
_add_if("HTTPS"         NOT CURL_DISABLE_HTTP AND SSL_ENABLED)
_add_if("FTP"           NOT CURL_DISABLE_FTP)
_add_if("FTPS"          NOT CURL_DISABLE_FTP AND SSL_ENABLED)
_add_if("FILE"          NOT CURL_DISABLE_FILE)
_add_if("TELNET"        NOT CURL_DISABLE_TELNET)
_add_if("LDAP"          NOT CURL_DISABLE_LDAP)
# CURL_DISABLE_LDAP implies CURL_DISABLE_LDAPS
# TODO check HAVE_LDAP_SSL (in autoconf this is enabled with --enable-ldaps)
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
_add_if("NSS"              SSL_ENABLED AND USE_NSS)
_add_if("wolfSSL"          SSL_ENABLED AND USE_WOLFSSL)
if(_items)
  list(SORT _items)
endif()
string(REPLACE ";" " " SSL_BACKENDS "${_items}")
message(STATUS "Enabled SSL backends: ${SSL_BACKENDS}")

# curl-config needs the following options to be set.
set(CC                      "${CMAKE_C_COMPILER}")
# TODO probably put a -D... options here?
set(CONFIGURE_OPTIONS       "")
# TODO when to set "-DCURL_STATICLIB" for CPPFLAG_CURL_STATICLIB?
set(CPPFLAG_CURL_STATICLIB  "")
set(CURLVERSION             "${CURL_VERSION}")
set(exec_prefix             "\${prefix}")
set(includedir              "\${prefix}/include")
set(LDFLAGS                 "${CMAKE_SHARED_LINKER_FLAGS}")
set(LIBCURL_LIBS            "")
set(libdir                  "${CMAKE_INSTALL_PREFIX}/lib")
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
  if(_lib MATCHES ".*/.*" OR _lib MATCHES "^-")
    set(LIBCURL_LIBS          "${LIBCURL_LIBS} ${_lib}")
  else()
    set(LIBCURL_LIBS          "${LIBCURL_LIBS} -l${_lib}")
  endif()
endforeach()
if(BUILD_SHARED_LIBS)
  set(ENABLE_SHARED         "yes")
  set(ENABLE_STATIC         "no")
  set(LIBCURL_NO_SHARED     "")
else()
  set(ENABLE_SHARED         "no")
  set(ENABLE_STATIC         "yes")
  set(LIBCURL_NO_SHARED     "${LIBCURL_LIBS}")
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

if(NOT TARGET uninstall)
  configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/CMake/cmake_uninstall.cmake.in
      ${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake
      IMMEDIATE @ONLY)

  add_custom_target(uninstall
      COMMAND ${CMAKE_COMMAND} -P
      ${CMAKE_CURRENT_BINARY_DIR}/CMake/cmake_uninstall.cmake)
endif()
