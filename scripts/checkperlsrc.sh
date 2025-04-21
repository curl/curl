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

#
# This script runs perltidy against all .pl and .pm files
#
# To format all .p[lm] files run:
#  > git ls-files -z "*.p[lm]" | xargs --null scripts/checkperlsrc.sh
#

set -eu

# perltidy options used (described in manpage https://perltidy.github.io/perltidy/perltidy.html#I-O-Control)
#
#  -b -bext '/' : Applies formatting changes to original file
#  -se : Use -se to cause all error messages to be sent to the standard error output stream
#  -w : Report any non-critical warning messages as errors
#  -l=79 : Default maximum line length
#  -bt=2 : Brace tightness
#  -pt=2 : Parens tightness
#  -sbt=2 : Square bracket tightness
#  -novalign : No attempt at vertical alignment
#  -baao : Break after all operators
#  -nsak='*' : No space after all keywords
#  -sak='my local our' : Space after specified keywords
#  -bol : Break at old logical breakpoints
#  -naws : No whitespace added
#  -fnl : Freeze newlines
#  -fws : Freeze whitespace
#  -nbbc : No blank line before comments

perltidy -b -bext '/' -se -w -l=79 -i=4 -bt=2 -pt=2 -sbt=2 -novalign -nsak='*' -sak='my local our' -bom -naws -fnl -fws -nbbc "$@"
