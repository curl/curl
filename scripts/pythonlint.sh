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

# Use ruff to perform a style analysis on all Python code in the supplied
# locations, or all Python files found in the current directory tree by
# default.

set -eu

ruff check --target-version=py38 \
  --extend-select=B007,B016,C405,C416,COM818,D200,D213,D204,D401,\
D415,FURB129,N818,PERF401,PERF403,PIE790,PIE808,PLW0127,Q004,RUF010,SIM101,\
SIM110,SIM117,SIM118,TRY400,TRY401,RET503,RET504,UP004,B018,B904,RSE102,RET505,\
I001,PERF102,C419 \
  --ignore=FA100 \
  "$@"
# Checks that are in preview only, since --preview otherwise turns them all on
ruff check --target-version=py38 --preview \
  --select=E301,E302,E303,E304,E305,E306,E502,FURB110,FURB113,FURB156,FURB171 \
  --ignore=RUF027 \
  "$@"
