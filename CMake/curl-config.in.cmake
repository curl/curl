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
@PACKAGE_INIT@

option(CURL_USE_PKGCONFIG "Enable pkg-config to detect @PROJECT_NAME@ dependencies. Default: @CURL_USE_PKGCONFIG@"
  "@CURL_USE_PKGCONFIG@")

if(CMAKE_VERSION VERSION_LESS @CMAKE_MINIMUM_REQUIRED_VERSION@)
  message(STATUS "@PROJECT_NAME@: @PROJECT_NAME@-specific Find modules require "
    "CMake @CMAKE_MINIMUM_REQUIRED_VERSION@ or upper, found: ${CMAKE_VERSION}.")
endif()

include(CMakeFindDependencyMacro)

if("@USE_OPENSSL@")
  if("@OPENSSL_VERSION_MAJOR@")
    find_dependency(OpenSSL "@OPENSSL_VERSION_MAJOR@")
  else()
    find_dependency(OpenSSL)
  endif()
endif()
if("@HAVE_LIBZ@")
  find_dependency(ZLIB "@ZLIB_VERSION_MAJOR@")
endif()

set(_curl_cmake_module_path_save ${CMAKE_MODULE_PATH})
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_MODULE_PATH})

set(_curl_libs "")

if("@HAVE_BROTLI@")
  find_dependency(Brotli)
  list(APPEND _curl_libs CURL::brotli)
endif()
if("@USE_ARES@")
  find_dependency(Cares)
  list(APPEND _curl_libs CURL::cares)
endif()
if("@HAVE_GSSAPI@")
  find_dependency(GSS)
  list(APPEND _curl_libs CURL::gss)
endif()
if("@USE_BACKTRACE@")
  find_dependency(Libbacktrace)
  list(APPEND _curl_libs CURL::libbacktrace)
endif()
if("@USE_GSASL@")
  find_dependency(Libgsasl)
  list(APPEND _curl_libs CURL::libgsasl)
endif()
if(NOT "@USE_WIN32_LDAP@" AND NOT "@CURL_DISABLE_LDAP@")
  find_dependency(LDAP)
  list(APPEND _curl_libs CURL::ldap)
endif()
if("@HAVE_LIBIDN2@")
  find_dependency(Libidn2)
  list(APPEND _curl_libs CURL::libidn2)
endif()
if("@USE_LIBPSL@")
  find_dependency(Libpsl)
  list(APPEND _curl_libs CURL::libpsl)
endif()
if("@USE_LIBRTMP@")
  find_dependency(Librtmp)
  list(APPEND _curl_libs CURL::librtmp)
endif()
if("@USE_LIBSSH@")
  find_dependency(Libssh)
  list(APPEND _curl_libs CURL::libssh)
endif()
if("@USE_LIBSSH2@")
  find_dependency(Libssh2)
  list(APPEND _curl_libs CURL::libssh2)
endif()
if("@USE_LIBUV@")
  find_dependency(Libuv)
  list(APPEND _curl_libs CURL::libuv)
endif()
if("@USE_MBEDTLS@")
  find_dependency(MbedTLS)
  list(APPEND _curl_libs CURL::mbedtls)
endif()
if("@USE_NGHTTP2@")
  find_dependency(NGHTTP2)
  list(APPEND _curl_libs CURL::nghttp2)
endif()
if("@USE_NGHTTP3@")
  find_dependency(NGHTTP3)
  list(APPEND _curl_libs CURL::nghttp3)
endif()
if("@USE_NGTCP2@")
  find_dependency(NGTCP2)
  list(APPEND _curl_libs CURL::ngtcp2)
endif()
if("@USE_GNUTLS@")
  find_dependency(GnuTLS)
  list(APPEND _curl_libs CURL::gnutls)
  find_dependency(Nettle)
  list(APPEND _curl_libs CURL::nettle)
endif()
if("@USE_QUICHE@")
  find_dependency(Quiche)
  list(APPEND _curl_libs CURL::quiche)
endif()
if("@USE_RUSTLS@")
  find_dependency(Rustls)
  list(APPEND _curl_libs CURL::rustls)
endif()
if("@USE_WOLFSSL@")
  find_dependency(WolfSSL)
  list(APPEND _curl_libs CURL::wolfssl)
endif()
if("@HAVE_ZSTD@")
  find_dependency(Zstd)
  list(APPEND _curl_libs CURL::zstd)
endif()

set(CMAKE_MODULE_PATH ${_curl_cmake_module_path_save})

if(WIN32 AND NOT TARGET CURL::win32_winsock)
  add_library(CURL::win32_winsock INTERFACE IMPORTED)
  set_target_properties(CURL::win32_winsock PROPERTIES INTERFACE_LINK_LIBRARIES "ws2_32")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/@TARGETS_EXPORT_NAME@.cmake")

# Alias for either shared or static library
if(NOT TARGET @PROJECT_NAME@::@LIB_NAME@)
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.11 AND CMAKE_VERSION VERSION_LESS 3.18)
    set_target_properties(@PROJECT_NAME@::@LIB_SELECTED@ PROPERTIES IMPORTED_GLOBAL TRUE)
  endif()
  add_library(@PROJECT_NAME@::@LIB_NAME@ ALIAS @PROJECT_NAME@::@LIB_SELECTED@)
endif()

if(TARGET @PROJECT_NAME@::@LIB_STATIC@)
  # CMake before CMP0099 (CMake 3.17 2020-03-20) did not propagate libdirs to
  # targets. It expected libs to have an absolute filename. As a workaround,
  # manually apply dependency libdirs, for CMake consumers without this policy.
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.17)
    cmake_policy(GET CMP0099 _has_CMP0099)  # https://cmake.org/cmake/help/latest/policy/CMP0099.html
  endif()
  if(NOT _has_CMP0099 AND CMAKE_VERSION VERSION_GREATER_EQUAL 3.13 AND _curl_libs)
    set(_curl_libdirs "")
    foreach(_curl_lib IN LISTS _curl_libs)
      get_target_property(_curl_libdir "${_curl_lib}" INTERFACE_LINK_DIRECTORIES)
      if(_curl_libdir)
        list(APPEND _curl_libdirs "${_curl_libdir}")
      endif()
    endforeach()
    if(_curl_libdirs)
      target_link_directories(@PROJECT_NAME@::@LIB_STATIC@ INTERFACE ${_curl_libdirs})
    endif()
  endif()
endif()

# For compatibility with CMake's FindCURL.cmake
set(CURL_VERSION_STRING "@CURLVERSION@")
set(CURL_LIBRARIES @PROJECT_NAME@::@LIB_NAME@)
set(CURL_LIBRARIES_PRIVATE "@LIBCURL_PC_LIBS_PRIVATE_LIST@")
set_and_check(CURL_INCLUDE_DIRS "@PACKAGE_CMAKE_INSTALL_INCLUDEDIR@")

set(CURL_SUPPORTED_PROTOCOLS "@CURL_SUPPORTED_PROTOCOLS_LIST@")
set(CURL_SUPPORTED_FEATURES "@CURL_SUPPORTED_FEATURES_LIST@")

foreach(_curl_item IN LISTS CURL_SUPPORTED_PROTOCOLS CURL_SUPPORTED_FEATURES)
  set(CURL_SUPPORTS_${_curl_item} TRUE)
endforeach()

set(_curl_missing_req "")
foreach(_curl_item IN LISTS CURL_FIND_COMPONENTS)
  if(CURL_SUPPORTS_${_curl_item})
    set(CURL_${_curl_item}_FOUND TRUE)
  elseif(CURL_FIND_REQUIRED_${_curl_item})
    list(APPEND _curl_missing_req ${_curl_item})
  endif()
endforeach()

if(_curl_missing_req)
  string(REPLACE ";" " " _curl_missing_req "${_curl_missing_req}")
  if(CURL_FIND_REQUIRED)
    message(FATAL_ERROR "@PROJECT_NAME@: missing required components: ${_curl_missing_req}")
  endif()
  unset(_curl_missing_req)
endif()

check_required_components("@PROJECT_NAME@")
