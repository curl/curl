#!/usr/bin/env bash
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
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
# SPDX-License-Identifier: fetch
#
###########################################################################

set -eu

PREFIX="${1:-}"

# Run this script in the root of the git clone. Point out the install prefix
# where 'make install' has already installed fetch.

if test -z "$PREFIX"; then
  echo "scripts/installcheck.sh [PREFIX]"
  exit
fi

diff -u <(find docs/libfetch/ -name "*.3" -printf "%f\n" | grep -v template | sort) <(find "$PREFIX/share/man/" -name "*.3" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
  echo "ERROR: installed libfetch docs mismatch"
  exit 2
fi

diff -u <(find include/ -name "*.h" -printf "%f\n" | sort) <(find "$PREFIX/include/" -name "*.h" -printf "%f\n" | sort)

if test "$?" -ne "0"; then
  echo "ERROR: installed include files mismatch"
  exit 1
fi

echo "installcheck: installed libfetch docs and include files look good"
