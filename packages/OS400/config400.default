#!/bin/sh
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

#                       Tunable configuration parameters.

setenv TARGETLIB        'CURL'                  # Target OS/400 program library.
setenv STATBNDDIR       'CURL_A'                # Static binding directory.
setenv DYNBNDDIR        'CURL'                  # Dynamic binding directory.
setenv SRVPGM           "CURL.${SONAME}"        # Service program.
setenv CURLPGM          'CURL'                  # CLI tool bound program.
setenv CURLCMD          'CURL'                  # CL command name.
setenv CURLCLI          'CURLCL'                # CL interface program.
setenv TGTCCSID         '500'                   # Target CCSID of objects.
setenv DEBUG            '*ALL'                  # Debug level.
setenv OPTIMIZE         '10'                    # Optimization level
setenv OUTPUT           '*NONE'                 # Compilation output option.
setenv TGTRLS           '*CURRENT'              # Target OS release.
setenv IFSDIR           '/curl'                 # Installation IFS directory.
setenv QADRTDIR         '/QIBM/ProdData/qadrt'  # QADRT IFS directory.
setenv PASEPERL         '/QOpenSys/pkgs/bin/perl'       # PASE Perl interpreter.

#       Define ZLIB availability and locations.

setenv WITH_ZLIB        0                       # Define to 1 to enable.
setenv ZLIB_INCLUDE     '/zlib/include'         # ZLIB include IFS directory.
setenv ZLIB_LIB         'ZLIB'                  # ZLIB library.
setenv ZLIB_BNDDIR      'ZLIB_A'                # ZLIB binding directory.

#       Define LIBSSH2 availability and locations.

setenv WITH_LIBSSH2     0                       # Define to 1 to enable.
setenv LIBSSH2_INCLUDE  '/libssh2/include'      # LIBSSH2 include IFS directory.
setenv LIBSSH2_LIB      'LIBSSH2'               # LIBSSH2 library.
setenv LIBSSH2_BNDDIR   'LIBSSH2_A'             # LIBSSH2 binding directory.
