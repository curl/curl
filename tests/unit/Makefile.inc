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

FIRSTFILES = \
 ../libtest/first.c \
 ../libtest/first.h

UNITFILES = curlcheck.h $(FIRSTFILES)

# These are all unit test programs
UNITPROGS = unit1300          unit1302 unit1303 unit1304 unit1305 unit1307 \
          unit1309 unit1323 \
 unit1330          unit1395 unit1396 unit1397 unit1398 \
 unit1399 \
 unit1600 unit1601 unit1602 unit1603          unit1605 unit1606 unit1607 \
 unit1608 unit1609 unit1610 unit1611 unit1612 unit1614 unit1615 unit1616 \
 unit1620 \
 unit1650 unit1651 unit1652 unit1653 unit1654 unit1655 unit1656 unit1657 \
 unit1658 \
 unit1660 unit1661 unit1663 unit1664 \
 unit1979 unit1980 \
 unit2600 unit2601 unit2602 unit2603 unit2604 \
 unit3200 \
 unit3205 \
 unit3211 unit3212 unit3213

unit1300_SOURCES = unit1300.c
unit1302_SOURCES = unit1302.c
unit1303_SOURCES = unit1303.c
unit1304_SOURCES = unit1304.c
unit1305_SOURCES = unit1305.c
unit1307_SOURCES = unit1307.c
unit1309_SOURCES = unit1309.c
unit1323_SOURCES = unit1323.c
unit1330_SOURCES = unit1330.c
unit1395_SOURCES = unit1395.c
unit1396_SOURCES = unit1396.c
unit1397_SOURCES = unit1397.c
unit1398_SOURCES = unit1398.c
unit1399_SOURCES = unit1399.c
unit1600_SOURCES = unit1600.c
unit1601_SOURCES = unit1601.c
unit1602_SOURCES = unit1602.c
unit1603_SOURCES = unit1603.c
unit1605_SOURCES = unit1605.c
unit1606_SOURCES = unit1606.c
unit1607_SOURCES = unit1607.c
unit1608_SOURCES = unit1608.c
unit1609_SOURCES = unit1609.c
unit1610_SOURCES = unit1610.c
unit1611_SOURCES = unit1611.c
unit1612_SOURCES = unit1612.c
unit1614_SOURCES = unit1614.c
unit1615_SOURCES = unit1615.c
unit1616_SOURCES = unit1616.c
unit1620_SOURCES = unit1620.c
unit1650_SOURCES = unit1650.c
unit1651_SOURCES = unit1651.c
unit1652_SOURCES = unit1652.c
unit1653_SOURCES = unit1653.c
unit1654_SOURCES = unit1654.c
unit1655_SOURCES = unit1655.c
unit1656_SOURCES = unit1656.c
unit1657_SOURCES = unit1657.c
unit1658_SOURCES = unit1658.c
unit1660_SOURCES = unit1660.c
unit1661_SOURCES = unit1661.c
unit1663_SOURCES = unit1663.c
unit1664_SOURCES = unit1664.c
unit1979_SOURCES = unit1979.c
unit1980_SOURCES = unit1980.c
unit2600_SOURCES = unit2600.c
unit2601_SOURCES = unit2601.c
unit2602_SOURCES = unit2602.c
unit2603_SOURCES = unit2603.c
unit2604_SOURCES = unit2604.c
unit3200_SOURCES = unit3200.c
unit3205_SOURCES = unit3205.c
unit3211_SOURCES = unit3211.c
unit3212_SOURCES = unit3212.c
unit3213_SOURCES = unit3213.c
