#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
# Python3 program to print all combination of size r in an array of size n.
# This is used to generate test lines in tests/ech_test.sh.
# This will be discarded in the process of moving from experimental,
# but is worth preserving for the moment in case of changes to the
# ECH command line args

def CombinationRepetitionUtil(chosen, arr, badarr, index,
                            r, start, end):

    # Current combination is ready,
    # print it
    if index == r:
        # figure out if result should be good or bad and
        # print prefix, assuming $turl does support ECH so
        # should work if given "positive" parameters
        res = 1
        j = len(chosen) - 1
        while res and j >= 0:
            if chosen[j] in badarr:
                res = 0
            j = j - 1
        print("cli_test $turl 1", res, end = " ")
        # print combination but eliminating any runs of
        # two identical params
        for j in range(r):
            if j != 0 and chosen[j] != chosen[j-1]:
                print(chosen[j], end = " ")

        print()
        return

    # When no more elements are
    # there to put in chosen[]
    if start > n:
        return

    # Current is included, put
    # next at next location
    chosen[index] = arr[start]

    # Current is excluded, replace it
    # with next (Note that i+1 is passed,
    # but index is not changed)
    CombinationRepetitionUtil(chosen, arr, badarr, index + 1,
                            r, start, end)
    CombinationRepetitionUtil(chosen, arr, badarr, index,
                            r, start + 1, end)

# The main function that prints all
# combinations of size r in arr[] of
# size n. This function mainly uses
# CombinationRepetitionUtil()
def CombinationRepetition(arr, badarr, n, r):

    # A temporary array to store
    # all combination one by one
    chosen = [0] * r

    # Print all combination using
    # temporary array 'chosen[]'
    CombinationRepetitionUtil(chosen, arr, badarr, 0, r, 0, n)

# Driver code
badarr = [ '--ech grease', '--ech false', '--ech ecl:$badecl', '--ech pn:$badpn' ]
goodarr = [ '--ech hard', '--ech true', '--ech ecl:$goodecl',  '--ech pn:$goodpn' ]
arr = badarr + goodarr
r = 8
n = len(arr) - 1

CombinationRepetition(arr, badarr, n, r)

# This code is contributed by Vaibhav Kumar 12.
