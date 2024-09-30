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
 unit1308 unit1309 unit1323 \
 unit1330 unit1394 unit1395 unit1396 unit1397 unit1398 \
 unit1399 \
 unit1600 unit1601 unit1602 unit1603 unit1604 unit1605 unit1606 unit1607 \
 unit1608 unit1609 unit1610 unit1611 unit1612 unit1614 unit1615 unit1616 \
 unit1620 unit1621 \
 unit1650 unit1651 unit1652 unit1653 unit1654 unit1655 unit1656 \
 unit1660 unit1661 unit1663 \
 unit2600 unit2601 unit2602 unit2603 unit2604 \
 unit3200 \
 unit3205

unit1300_SOURCES = unit1300.c $(UNITFILES)

unit1302_SOURCES = unit1302.c $(UNITFILES)

unit1303_SOURCES = unit1303.c $(UNITFILES)

unit1304_SOURCES = unit1304.c $(UNITFILES)

unit1305_SOURCES = unit1305.c $(UNITFILES)

unit1307_SOURCES = unit1307.c $(UNITFILES)

unit1308_SOURCES = unit1308.c $(UNITFILES)

unit1309_SOURCES = unit1309.c $(UNITFILES)

unit1323_SOURCES = unit1323.c $(UNITFILES)

unit1330_SOURCES = unit1330.c $(UNITFILES)

unit1394_SOURCES = unit1394.c $(UNITFILES)

unit1395_SOURCES = unit1395.c $(UNITFILES)

unit1396_SOURCES = unit1396.c $(UNITFILES)

unit1397_SOURCES = unit1397.c $(UNITFILES)

unit1398_SOURCES = unit1398.c $(UNITFILES)

unit1399_SOURCES = unit1399.c $(UNITFILES)

unit1600_SOURCES = unit1600.c $(UNITFILES)

unit1601_SOURCES = unit1601.c $(UNITFILES)

unit1602_SOURCES = unit1602.c $(UNITFILES)

unit1603_SOURCES = unit1603.c $(UNITFILES)

unit1604_SOURCES = unit1604.c $(UNITFILES)

unit1605_SOURCES = unit1605.c $(UNITFILES)

unit1606_SOURCES = unit1606.c $(UNITFILES)

unit1607_SOURCES = unit1607.c $(UNITFILES)

unit1608_SOURCES = unit1608.c $(UNITFILES)

unit1609_SOURCES = unit1609.c $(UNITFILES)

unit1610_SOURCES = unit1610.c $(UNITFILES)

unit1611_SOURCES = unit1611.c $(UNITFILES)

unit1612_SOURCES = unit1612.c $(UNITFILES)

unit1614_SOURCES = unit1614.c $(UNITFILES)

unit1615_SOURCES = unit1615.c $(UNITFILES)

unit1616_SOURCES = unit1616.c $(UNITFILES)

unit1620_SOURCES = unit1620.c $(UNITFILES)

unit1621_SOURCES = unit1621.c $(UNITFILES)

unit1650_SOURCES = unit1650.c $(UNITFILES)

unit1651_SOURCES = unit1651.c $(UNITFILES)

unit1652_SOURCES = unit1652.c $(UNITFILES)

unit1653_SOURCES = unit1653.c $(UNITFILES)

unit1654_SOURCES = unit1654.c $(UNITFILES)

unit1655_SOURCES = unit1655.c $(UNITFILES)

unit1656_SOURCES = unit1656.c $(UNITFILES)

unit1660_SOURCES = unit1660.c $(UNITFILES)

unit1661_SOURCES = unit1661.c $(UNITFILES)

unit1663_SOURCES = unit1663.c $(UNITFILES)

unit2600_SOURCES = unit2600.c $(UNITFILES)

unit2601_SOURCES = unit2601.c $(UNITFILES)

unit2602_SOURCES = unit2602.c $(UNITFILES)

unit2603_SOURCES = unit2603.c $(UNITFILES)

unit2604_SOURCES = unit2604.c $(UNITFILES)

unit3200_SOURCES = unit3200.c $(UNITFILES)

unit3205_SOURCES = unit3205.c $(UNITFILES)
