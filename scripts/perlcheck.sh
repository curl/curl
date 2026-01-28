#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Dan Fandrich, <dan@coneharvesters.com>, Viktor Szakats, et al.
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

# The xargs invocation is portable, but does not preserve spaces in filenames.
# If such a file is ever added, then this can be portably fixed by switching to
# "xargs -I{}" and appending {} to the end of the xargs arguments (which will
# call cmakelint once per file) or by using the GNU extension "xargs -d'\n'".

set -eu

cd "$(dirname "$0")"/..

procs=6
command -v nproc >/dev/null && procs="$(nproc)"
echo "parallel: ${procs}"

{
  if [ -n "${1:-}" ]; then
    for A in "$@"; do printf '%s\n' "$A"; done
  elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files '*.pl' '*.pm'
    git grep -l '^#!/usr/bin/env perl'
  else
    find . -type f \( -name '*.pl' -o -name '*.pm' \)
  fi
} | sort -u | xargs -n 1 -P "${procs}" perl -c -Itests --
