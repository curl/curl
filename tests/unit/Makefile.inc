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
# Shared between CMakeLists.txt and Makefile.am

BUNDLE = units

# Files referenced from the bundle source
FIRST_C = ../libtest/first.c

# All unit test programs
TESTS_C = \
  unit1300.c            unit1302.c unit1303.c unit1304.c unit1305.c \
  unit1307.c            unit1309.c \
  unit1323.c unit1330.c \
  unit1395.c unit1396.c unit1397.c unit1398.c unit1399.c \
  unit1600.c unit1601.c unit1602.c unit1603.c            unit1605.c unit1606.c \
  unit1607.c unit1608.c unit1609.c unit1610.c unit1611.c unit1612.c unit1614.c \
  unit1615.c unit1616.c                                  unit1620.c \
  unit1650.c unit1651.c unit1652.c unit1653.c unit1654.c unit1655.c unit1656.c \
  unit1657.c unit1658.c            unit1660.c unit1661.c unit1663.c unit1664.c \
  unit1979.c unit1980.c \
  unit2600.c unit2601.c unit2602.c unit2603.c unit2604.c \
  unit3200.c                                             unit3205.c \
  unit3211.c unit3212.c unit3213.c unit3214.c
