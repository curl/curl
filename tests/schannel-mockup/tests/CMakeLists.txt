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

set(TEST_PROGRAMS
  test_credentials
  test_sspi_handshake
  test_encrypt_decrypt
  test_crypto_store
)

foreach(_test_name ${TEST_PROGRAMS})
  add_executable(${_test_name} "${_test_name}.c")
  target_link_libraries(${_test_name} PRIVATE
    schannelmockup
    OpenSSL::SSL
    OpenSSL::Crypto
  )
  add_test(NAME ${_test_name} COMMAND ${_test_name})
endforeach()

if(PERL_EXECUTABLE AND EXISTS "${_checksrc}")
  add_custom_target(checksrc-tests
    COMMAND ${PERL_EXECUTABLE} "${_checksrc}" -D.
      test_credentials.c
      test_sspi_handshake.c
      test_encrypt_decrypt.c
      test_crypto_store.c
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "RUN      checksrc in tests"
    VERBATIM
  )
endif()
