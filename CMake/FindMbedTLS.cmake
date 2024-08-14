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
# Find the mbedtls library
#
# Result Variables:
#
# MBEDTLS_FOUND         System has mbedtls
# MBEDTLS_INCLUDE_DIRS  The mbedtls include directories
# MBEDTLS_LIBRARIES     The mbedtls library names

# for compatibility. Configuration via MBEDTLS_INCLUDE_DIRS is deprecated, use MBEDTLS_INCLUDE_DIR instead.
if(DEFINED MBEDTLS_INCLUDE_DIRS AND NOT DEFINED MBEDTLS_INCLUDE_DIR)
  set(MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
  unset(MBEDTLS_INCLUDE_DIRS)
endif()

find_path(MBEDTLS_INCLUDE_DIR "mbedtls/ssl.h")

find_library(MBEDTLS_LIBRARY "mbedtls")
find_library(MBEDX509_LIBRARY "mbedx509")
find_library(MBEDCRYPTO_LIBRARY "mbedcrypto")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS
    MBEDTLS_INCLUDE_DIR
    MBEDTLS_LIBRARY
    MBEDX509_LIBRARY
    MBEDCRYPTO_LIBRARY
)

if(MBEDTLS_FOUND)
  set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
  set(MBEDTLS_LIBRARIES    ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
