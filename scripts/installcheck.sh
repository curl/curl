#!/bin/bash
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

PREFIX=$1

# Run this script in the root of the git clone. Point out the install prefix
# where 'make install' has already installed curl.

if test -z "$1";  then
    echo "scripts/installcheck.sh [PREFIX]"
    exit
fi

diff -u <(find docs/libcurl/ -name "*.3" -printf "%f\n" | grep -v template| sort) <(find $PREFIX/share/man/ -name "*.3" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
    echo "ERROR: installed libcurl docs mismatch"
    exit 2
fi

diff -u <(find include/ -name "*.h" -printf "%f\n" | sort) <(find $PREFIX/include/ -name "*.h" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
    echo "ERROR: installed include files mismatch"
    exit 1
fi

echo "installcheck: installed libcurl docs and include files look good"
