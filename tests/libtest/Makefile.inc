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

BUNDLE = libtests

# Files referenced from the bundle source
FIRST_C = first.c
FIRST_H = first.h

# Common files used by test programs
UTILS_C = memptr.c testutil.c testtrace.c
UTILS_H = testutil.h testtrace.h unitcheck.h

CURLX_C = \
  ../../lib/curlx/warnless.c \
  ../../lib/curlx/multibyte.c \
  ../../lib/curlx/timediff.c \
  ../../lib/curlx/timeval.c \
  ../../lib/curl_threads.c \
  ../../lib/curlx/version_win32.c \
  ../../lib/curlx/wait.c

# All libtest programs
TESTS_C = \
  cli_h2_pausing.c \
  cli_h2_serverpush.c \
  cli_h2_upgrade_extreme.c \
  cli_hx_download.c \
  cli_hx_upload.c \
  cli_tls_session_reuse.c \
  cli_upload_pausing.c \
  cli_ws_data.c \
  cli_ws_pingpong.c \
  \
  lib500.c lib501.c lib502.c lib503.c lib504.c lib505.c lib506.c lib507.c \
  lib508.c lib509.c lib510.c lib511.c lib512.c lib513.c lib514.c lib515.c \
  lib516.c lib517.c lib518.c lib519.c lib520.c lib521.c lib523.c lib524.c \
  lib525.c lib526.c                            lib530.c \
  lib533.c                   lib536.c lib537.c lib539.c lib540.c lib541.c \
  lib542.c lib543.c lib544.c                   lib547.c          lib549.c \
  lib552.c lib553.c lib554.c lib555.c lib556.c lib557.c lib558.c lib559.c \
  lib560.c          lib562.c          lib564.c          lib566.c lib567.c \
  lib568.c lib569.c lib570.c lib571.c lib572.c lib573.c lib574.c lib575.c \
  lib576.c          lib578.c lib579.c lib582.c lib583.c \
  lib586.c                   lib589.c lib590.c lib591.c \
  lib597.c lib598.c lib599.c \
  lib643.c \
  lib650.c lib651.c lib652.c lib653.c lib654.c lib655.c lib658.c lib659.c \
  lib661.c                                     lib666.c lib667.c lib668.c \
  lib670.c                            lib674.c lib676.c lib677.c lib678.c \
  lib694.c lib695.c \
  lib751.c          lib753.c                                     lib758.c \
  lib757.c \
  lib1156.c \
  lib1301.c                                                   lib1308.c \
  lib1485.c \
  lib1500.c lib1501.c lib1502.c                               lib1506.c \
  lib1507.c lib1508.c lib1509.c lib1510.c lib1511.c lib1512.c lib1513.c \
  lib1514.c lib1515.c           lib1517.c lib1518.c           lib1520.c \
  lib1522.c lib1523.c           lib1525.c lib1526.c lib1527.c lib1528.c \
  lib1529.c lib1530.c lib1531.c lib1532.c lib1533.c lib1534.c lib1535.c \
  lib1536.c lib1537.c lib1538.c           lib1540.c lib1541.c lib1542.c \
  lib1545.c                               lib1549.c lib1550.c lib1551.c \
  lib1552.c lib1553.c lib1554.c lib1555.c lib1556.c lib1557.c lib1558.c \
  lib1559.c lib1560.c                               lib1564.c lib1565.c \
  lib1567.c lib1568.c lib1569.c           lib1571.c \
  lib1576.c \
  lib1591.c lib1592.c lib1593.c lib1594.c                     lib1597.c \
  lib1598.c lib1599.c \
  lib1662.c \
  lib1900.c lib1901.c           lib1903.c lib1905.c lib1906.c lib1907.c \
  lib1908.c           lib1910.c lib1911.c lib1912.c lib1913.c \
  lib1915.c lib1916.c           lib1918.c lib1919.c \
  lib1933.c lib1934.c lib1935.c lib1936.c lib1937.c lib1938.c lib1939.c \
  lib1940.c                                         lib1945.c \
  lib1947.c lib1948.c \
  lib1955.c lib1956.c lib1957.c lib1958.c lib1959.c lib1960.c \
  lib1964.c                                                   lib1970.c \
  lib1971.c lib1972.c lib1973.c lib1974.c lib1975.c lib1977.c lib1978.c \
  lib2023.c lib2032.c lib2082.c \
  lib2301.c lib2302.c lib2304.c           lib2306.c lib2308.c lib2309.c \
  lib2402.c           lib2404.c lib2405.c \
  lib2502.c \
  lib2700.c \
  lib3010.c lib3025.c lib3026.c lib3027.c lib3033.c lib3034.c \
  lib3100.c lib3101.c lib3102.c lib3103.c lib3104.c lib3105.c \
  lib3207.c lib3208.c
