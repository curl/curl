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

find_program(CADDY "caddy")  # /usr/bin/caddy
if(NOT CADDY)
  set(CADDY "")
endif()
mark_as_advanced(CADDY)

find_program(VSFTPD "vsftpd")  # /usr/sbin/vsftpd
if(NOT VSFTPD)
  set(VSFTPD "")
endif()
mark_as_advanced(VSFTPD)

find_program(HTTPD NAMES "/usr/sbin/apache2" "httpd" "apache2")
if(NOT HTTPD)
  set(HTTPD "")
endif()
mark_as_advanced(HTTPD)

find_program(APXS "apxs")
if(NOT APXS)
  set(APXS "")
endif()
mark_as_advanced(APXS)

find_program(HTTPD_NGHTTPX "nghttpx" PATHS "/usr/bin" "/usr/local/bin")
if(NOT HTTPD_NGHTTPX)
  set(HTTPD_NGHTTPX "")
endif()
mark_as_advanced(HTTPD_NGHTTPX)

find_program(DANTED "danted")
if(NOT DANTED)
  set(DANTED "")
endif()
mark_as_advanced(DANTED)

# Consumed variables: APXS, CADDY, HTTPD, HTTPD_NGHTTPX, DANTED, VSFTPD
configure_file("config.ini.in" "${CMAKE_CURRENT_BINARY_DIR}/config.ini" @ONLY)
