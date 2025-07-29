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

ruff check --extend-select=B007,B016,C405,C416,COM818,D200,D213,D204,D401,D415,FURB129,N818,PERF401,PERF403,PIE790,PIE808,PLW0127,Q004,RUF010,SIM101,SIM117,SIM118,TRY400,TRY401 "$@"
