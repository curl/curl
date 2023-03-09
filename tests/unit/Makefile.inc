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

# these files are used in every single unit test program

UNITFILES = curlcheck.h \
 ../libtest/test.h \
 ../libtest/first.c

# These are all unit test programs
UNITPROGS = unit1300          unit1302 unit1303 unit1304 unit1305 unit1307 \
 unit1308 unit1309 unit1323 \
 unit1330 unit1394 unit1395 unit1396 unit1397 unit1398 \
 unit1399 \
 unit1600 unit1601 unit1602 unit1603 unit1604 unit1605 unit1606 unit1607 \
 unit1608 unit1609 unit1610 unit1611 unit1612 unit1614 \
 unit1620 unit1621 \
 unit1650 unit1651 unit1652 unit1653 unit1654 unit1655 \
 unit1660 unit1661 \
 unit2600 \
 unit3200
