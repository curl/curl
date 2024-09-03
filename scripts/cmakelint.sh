#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Dan Fandrich, <dan@coneharvesters.com>, et al.
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

# Run cmakelint on the curl source code. It will check all files given on the
# command-line, or else all relevant files in git, or if not in a git
# repository, all files starting in the tree rooted in the current directory.
#
# cmakelint can be installed from PyPi with the command "python3 -m pip install
# cmakelint".
#
# The xargs invocation is portable, but does not preserve spaces in file names.
# If such a file is ever added, then this can be portably fixed by switching to
# "xargs -I{}" and appending {} to the end of the xargs arguments (which will
# call cmakelint once per file) or by using the GNU extension "xargs -d'\n'".
{
  if [ -n "$1" ]; then
    for A in "$@"; do printf "%s\n" "$A"; done
  elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files
  else
    # strip off the leading ./ to make the grep regexes work properly
    find . -type f | sed 's@^\./@@'
  fi
} | grep -E '(/CMake|\.cmake$)' | grep -v -E '(\.h\.cmake|\.in)$' \
  | xargs \
  cmakelint \
    --spaces=2 --linelength=132 \
    --filter=-whitespace/indent,-convention/filename,-package/stdargs
