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
# files used only in some libcurl test programs
TESTUTIL = testutil.c testutil.h testtrace.c testtrace.h
WARNLESS = ../../lib/curlx/warnless.c ../../lib/curlx/warnless.h ../../lib/curlx/multibyte.c ../../lib/curlx/multibyte.h ../../lib/curlx/timediff.c ../../lib/curlx/timediff.h ../../lib/curl_threads.c ../../lib/curl_threads.h
MEMPTR = memptr.c

# these files are used in every single test program below
FIRSTFILES = first.c first.h

# These are all libcurl test programs
LIBTESTPROGS = libauthretry libntlmconnect libprereq                     \
 lib500 lib501 lib502 lib503 lib504 lib505 lib506 lib507 lib508 lib509   \
 lib510 lib511 lib512 lib513 lib514 lib515 lib516 lib517 lib518 lib519   \
 lib520 lib521 lib523 lib524 lib525 lib526               lib530          \
 lib533               lib536 lib537 lib539 lib540 lib541 lib542 lib543   \
 lib544                                                                  \
 lib547        lib549 lib552 lib553 lib554 lib555 lib556 lib557 lib558   \
 lib559 lib560 lib562 lib564        lib566 lib567 lib568 lib569 lib570   \
 lib571 lib572 lib573 lib574 lib575 lib576        lib578 lib579 lib582   \
 lib583               lib586        lib589 lib590 lib591 lib597 lib598   \
 lib599 \
 lib643               lib650 lib651 lib652 lib653 lib654 lib655 lib658   \
 lib659 lib661 lib666 lib667 lib668 \
 lib670                      lib674 lib676 lib677 lib678 lib694 lib695   \
 lib751 \
 lib1156 \
 lib1301 \
 lib1308 \
 lib1485 \
 lib1500 lib1501 lib1502                         lib1506 lib1507 lib1508 \
 lib1509 lib1510 lib1511 lib1512 lib1513 lib1514 lib1515         lib1517 \
 lib1518         lib1520 lib1521 lib1522 lib1523 \
 lib1525 lib1526 lib1527 lib1528 lib1529 lib1530 lib1531 lib1532 lib1533 \
 lib1534 lib1535 lib1536 lib1537 lib1538 \
 lib1540 lib1541 lib1542                 lib1545 \
 lib1550 lib1551 lib1552 lib1553 lib1554 lib1555 lib1556 lib1557 \
 lib1558 lib1559 lib1560 lib1564 lib1565 lib1567 lib1568 lib1569 lib1571 \
                         lib1576 \
 lib1591 lib1592 lib1593 lib1594         lib1597 lib1598 \
 \
 lib1662 \
 \
 lib1900 lib1901 \
 lib1903 lib1905 lib1906 lib1907 lib1908 lib1910 lib1911 lib1912 lib1913 \
         lib1915 lib1916         lib1918 lib1919 \
 lib1933 lib1934 lib1935 lib1936 lib1937 lib1938 lib1939 lib1940 \
 lib1945         lib1947 lib1948 lib1955 lib1956 lib1957 lib1958 lib1959 \
 lib1960 lib1964 \
 lib1970 lib1971 lib1972 lib1973 lib1974 lib1975 lib1977 lib1978 \
 lib2301 lib2302 lib2304 lib2306 lib2308 lib2309 \
 lib2402 lib2404 lib2405 \
 lib2502 \
 lib2700 \
 lib3010 lib3025 lib3026 lib3027 \
 lib3100 lib3101 lib3102 lib3103 lib3104 lib3105 lib3207 lib3208

libntlmconnect_SOURCES = libntlmconnect.c
libauthretry_SOURCES = libauthretry.c
libprereq_SOURCES = libprereq.c
lib500_SOURCES = lib500.c
lib501_SOURCES = lib501.c
lib502_SOURCES = lib502.c
lib503_SOURCES = lib503.c
lib504_SOURCES = lib504.c
lib505_SOURCES = lib505.c
lib506_SOURCES = lib506.c
lib507_SOURCES = lib507.c
lib508_SOURCES = lib508.c
lib509_SOURCES = lib509.c
lib510_SOURCES = lib510.c
lib511_SOURCES = lib511.c
lib512_SOURCES = lib512.c
lib513_SOURCES = lib513.c
lib514_SOURCES = lib514.c
lib515_SOURCES = lib515.c
lib516_SOURCES = lib516.c
lib517_SOURCES = lib517.c
lib518_SOURCES = lib518.c
lib519_SOURCES = lib519.c
lib520_SOURCES = lib520.c
lib521_SOURCES = lib521.c
lib523_SOURCES = lib523.c
lib524_SOURCES = lib524.c
lib525_SOURCES = lib525.c
lib526_SOURCES = lib526.c
lib530_SOURCES = lib530.c
lib533_SOURCES = lib533.c
lib536_SOURCES = lib536.c
lib537_SOURCES = lib537.c
lib539_SOURCES = lib539.c
lib540_SOURCES = lib540.c
lib541_SOURCES = lib541.c
lib542_SOURCES = lib542.c
lib543_SOURCES = lib543.c
lib544_SOURCES = lib544.c
lib547_SOURCES = lib547.c
lib549_SOURCES = lib549.c
lib552_SOURCES = lib552.c
lib553_SOURCES = lib553.c
lib554_SOURCES = lib554.c
lib555_SOURCES = lib555.c
lib556_SOURCES = lib556.c
lib557_SOURCES = lib557.c
lib558_SOURCES = lib558.c
lib559_SOURCES = lib559.c
lib560_SOURCES = lib560.c
lib562_SOURCES = lib562.c
lib564_SOURCES = lib564.c
lib566_SOURCES = lib566.c
lib567_SOURCES = lib567.c
lib568_SOURCES = lib568.c
lib569_SOURCES = lib569.c
lib570_SOURCES = lib570.c
lib571_SOURCES = lib571.c
lib572_SOURCES = lib572.c
lib573_SOURCES = lib573.c
lib574_SOURCES = lib574.c
lib575_SOURCES = lib575.c
lib576_SOURCES = lib576.c
lib578_SOURCES = lib578.c
lib579_SOURCES = lib579.c
lib582_SOURCES = lib582.c
lib583_SOURCES = lib583.c
lib586_SOURCES = lib586.c
lib589_SOURCES = lib589.c
lib590_SOURCES = lib590.c
lib591_SOURCES = lib591.c
lib597_SOURCES = lib597.c
lib598_SOURCES = lib598.c
lib599_SOURCES = lib599.c
lib643_SOURCES = lib643.c
lib650_SOURCES = lib650.c
lib651_SOURCES = lib651.c
lib652_SOURCES = lib652.c
lib653_SOURCES = lib653.c
lib654_SOURCES = lib654.c
lib655_SOURCES = lib655.c
lib658_SOURCES = lib658.c
lib659_SOURCES = lib659.c
lib661_SOURCES = lib661.c
lib666_SOURCES = lib666.c
lib667_SOURCES = lib667.c
lib668_SOURCES = lib668.c
lib670_SOURCES = lib670.c
lib674_SOURCES = lib674.c
lib676_SOURCES = lib676.c
lib677_SOURCES = lib677.c
lib678_SOURCES = lib678.c
lib694_SOURCES = lib694.c
lib695_SOURCES = lib695.c
lib751_SOURCES = lib751.c
lib1301_SOURCES = lib1301.c
lib1308_SOURCES = lib1308.c
lib1485_SOURCES = lib1485.c
lib1500_SOURCES = lib1500.c
lib1501_SOURCES = lib1501.c
lib1502_SOURCES = lib1502.c
lib1506_SOURCES = lib1506.c
lib1156_SOURCES = lib1156.c
lib1507_SOURCES = lib1507.c
lib1508_SOURCES = lib1508.c
lib1509_SOURCES = lib1509.c
lib1510_SOURCES = lib1510.c
lib1511_SOURCES = lib1511.c
lib1512_SOURCES = lib1512.c
lib1513_SOURCES = lib1513.c
lib1514_SOURCES = lib1514.c
lib1515_SOURCES = lib1515.c
lib1517_SOURCES = lib1517.c
lib1518_SOURCES = lib1518.c
lib1520_SOURCES = lib1520.c
nodist_lib1521_SOURCES = lib1521.c
lib1522_SOURCES = lib1522.c
lib1523_SOURCES = lib1523.c
lib1525_SOURCES = lib1525.c
lib1526_SOURCES = lib1526.c
lib1527_SOURCES = lib1527.c
lib1528_SOURCES = lib1528.c
lib1529_SOURCES = lib1529.c
lib1530_SOURCES = lib1530.c
lib1531_SOURCES = lib1531.c
lib1532_SOURCES = lib1532.c
lib1533_SOURCES = lib1533.c
lib1534_SOURCES = lib1534.c
lib1535_SOURCES = lib1535.c
lib1536_SOURCES = lib1536.c
lib1537_SOURCES = lib1537.c
lib1538_SOURCES = lib1538.c
lib1540_SOURCES = lib1540.c
lib1541_SOURCES = lib1541.c
lib1542_SOURCES = lib1542.c
lib1545_SOURCES = lib1545.c
lib1550_SOURCES = lib1550.c
lib1551_SOURCES = lib1551.c
lib1552_SOURCES = lib1552.c
lib1553_SOURCES = lib1553.c
lib1554_SOURCES = lib1554.c
lib1555_SOURCES = lib1555.c
lib1556_SOURCES = lib1556.c
lib1557_SOURCES = lib1557.c
lib1558_SOURCES = lib1558.c
lib1559_SOURCES = lib1559.c
lib1560_SOURCES = lib1560.c
lib1564_SOURCES = lib1564.c
lib1565_SOURCES = lib1565.c
lib1567_SOURCES = lib1567.c
lib1568_SOURCES = lib1568.c
lib1569_SOURCES = lib1569.c
lib1571_SOURCES = lib1571.c
lib1576_SOURCES = lib1576.c
lib1591_SOURCES = lib1591.c
lib1592_SOURCES = lib1592.c
lib1593_SOURCES = lib1593.c
lib1594_SOURCES = lib1594.c
lib1597_SOURCES = lib1597.c
lib1598_SOURCES = lib1598.c
lib1662_SOURCES = lib1662.c
lib1900_SOURCES = lib1900.c
lib1901_SOURCES = lib1901.c
lib1903_SOURCES = lib1903.c
lib1905_SOURCES = lib1905.c
lib1906_SOURCES = lib1906.c
lib1907_SOURCES = lib1907.c
lib1908_SOURCES = lib1908.c
lib1910_SOURCES = lib1910.c
lib1911_SOURCES = lib1911.c
lib1912_SOURCES = lib1912.c
lib1913_SOURCES = lib1913.c
lib1915_SOURCES = lib1915.c
lib1916_SOURCES = lib1916.c
lib1918_SOURCES = lib1918.c
lib1919_SOURCES = lib1919.c
lib1933_SOURCES = lib1933.c
lib1934_SOURCES = lib1934.c
lib1935_SOURCES = lib1935.c
lib1936_SOURCES = lib1936.c
lib1937_SOURCES = lib1937.c
lib1938_SOURCES = lib1938.c
lib1939_SOURCES = lib1939.c
lib1940_SOURCES = lib1940.c
lib1945_SOURCES = lib1945.c
lib1947_SOURCES = lib1947.c
lib1948_SOURCES = lib1948.c
lib1955_SOURCES = lib1955.c
lib1956_SOURCES = lib1956.c
lib1957_SOURCES = lib1957.c
lib1958_SOURCES = lib1958.c
lib1959_SOURCES = lib1959.c
lib1960_SOURCES = lib1960.c
lib1964_SOURCES = lib1964.c
lib1970_SOURCES = lib1970.c
lib1971_SOURCES = lib1971.c
lib1972_SOURCES = lib1972.c
lib1973_SOURCES = lib1973.c
lib1974_SOURCES = lib1974.c
lib1975_SOURCES = lib1975.c
lib1977_SOURCES = lib1977.c
lib1978_SOURCES = lib1978.c
lib2301_SOURCES = lib2301.c
lib2302_SOURCES = lib2302.c
lib2304_SOURCES = lib2304.c
lib2306_SOURCES = lib2306.c
lib2308_SOURCES = lib2308.c
lib2309_SOURCES = lib2309.c
lib2402_SOURCES = lib2402.c
lib2404_SOURCES = lib2404.c
lib2405_SOURCES = lib2405.c
lib2502_SOURCES = lib2502.c
lib2700_SOURCES = lib2700.c
lib3010_SOURCES = lib3010.c
lib3025_SOURCES = lib3025.c
lib3026_SOURCES = lib3026.c
lib3027_SOURCES = lib3027.c
lib3100_SOURCES = lib3100.c
lib3101_SOURCES = lib3101.c
lib3102_SOURCES = lib3102.c
lib3103_SOURCES = lib3103.c
lib3104_SOURCES = lib3104.c
lib3105_SOURCES = lib3105.c
lib3207_SOURCES = lib3207.c
lib3208_SOURCES = lib3208.c
