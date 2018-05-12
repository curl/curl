#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

# this list is in numerical order
TESTCASES = test1 test2 test3 test4 test5 test6 test7 test8 test9       \
test10 test11 test12 test13 test14 test15 test16 test17 test18 test19   \
test20 test21 test22 test23 test24 test25 test26 test27 test28 test29   \
test30 test31 test32 test33 test34 test35 test36 test37 test38 test39   \
test40 test41 test42 test43 test44 test45 test46 test47 test48 test49   \
test50 test51 test52 test53 test54 test55 test56 test57 test58 test59   \
test60 test61 test62 test63 test64 test65 test66 test67 test68 test69   \
test70 test71 test72 test73 test74 test75 test76 test77 test78 test79   \
test80 test81 test82 test83 test84 test85 test86 test87 test88 test89   \
test90 test91 test92 test93 test94 test95 test96 test97 test98 test99   \
test100 test101 test102 test103 test104 test105 test106 test107 test108 \
test109 test110 test111 test112 test113 test114 test115 test116 test117 \
test118 test119 test120 test121 test122 test123 test124 test125 test126 \
test127 test128 test129 test130 test131 test132 test133 test134 test135 \
test136 test137 test138 test139 test140 test141 test142 test143 test144 \
test145 test146 test147 test148 test149 test150 test151 test152 test153 \
test154 test155 test156 test157 test158 test159 test160 test161 test162 \
test163 test164 test165 test166 test167 test168 test169 test170 test171 \
test172 test173 test174 test175 test176 test177 test178 test179 test180 \
test181 test182 test183 test184 test185 test186 test187 test188 test189 \
test190 test191 test192 test193 test194 test195 test196 test197 test198 \
test199 test200 test201 test202 test203 test204 test205 test206 test207 \
test208 test209 test210 test211 test212 test213 test214 test215 test216 \
test217 test218 test219 test220 test221 test222 test223 test224 test225 \
test226 test227 test228 test229 test230 test231 test232 test233 test234 \
test235 test236 test237 test238 test239 test240 test241 test242 test243 \
test244 test245 test246 test247 test248 test249 test250 test251 test252 \
test253 test254 test255 test256 test257 test258 test259 test260 test261 \
test262 test263 test264 test265 test266 test267 test268 test269 test270 \
test271 test272 test273 test274 test275 test276 test277 test278 test279 \
test280 test281 test282 test283 test284 test285 test286 test287 test288 \
test289 test290 test291 test292 test293 test294 test295 test296 test297 \
test298 test299 test300 test301 test302 test303 test304 test305 test306 \
test307 test308 test309 test310 test311 test312 test313 test314 test315 \
test316 test317 test318 test319 test320 test321 test322 test323 test324 \
test325 test326 \
\
test340 \
\
test350 test351 test352 test353 test354 \
test393 test394 test395 \
\
test400 test401 test402 test403 test404 test405 test406 test407 test408 \
test409 \
\
test500 test501 test502 test503 test504 test505 test506 test507 test508 \
test509 test510 test511 test512 test513 test514 test515 test516 test517 \
test518 test519 test520 test521 test522 test523 test524 test525 test526 \
test527 test528 test529 test530 test531 test532 test533 test534 test535 \
test536 test537 test538 test539 test540 test541 test542 test543 test544 \
test545 test546 test547 test548 test549 test550 test551 test552 test553 \
test554 test555 test556 test557 test558 test559 test560 test561 test562 \
test563 test564 test565 test566 test567 test568 test569 test570 test571 \
test572 test573 test574 test575 test576 test577 test578 test579 test580 \
test581 test582 test583 test584 test585 test586 test587 test588 test589 \
test590 test591 test592 test593 test594 test595 test596 test597 test598 \
test599 test600 test601 test602 test603 test604 test605 test606 test607 \
test608 test609 test610 test611 test612 test613 test614 test615 test616 \
test617 test618 test619 test620 test621 test622 test623 test624 test625 \
test626 test627 test628 test629 test630 test631 test632 test633 test634 \
test635 test636 test637 test638 test639 test640 test641 test642 \
test643 test644 test645 test646 test647 test648 test649 test650 test651 \
test652 test653 test654 test655 \
\
test700 test701 test702 test703 test704 test705 test706 test707 test708 \
test709 test710 test711 test712 test713 test714 test715 \
\
test800 test801 test802 test803 test804 test805 test806 test807 test808 \
test809 test810 test811 test812 test813 test814 test815 test816 test817 \
test818 test819 test820 test821 test822 test823 test824 test825 test826 \
test827 test828 test829 test830 test831 test832 test833 test834 test835 \
test836 test837 test838 test839 test840 test841 test842 test843 test844 \
test845 test846 \
\
test850 test851 test852 test853 test854 test855 test856 test857 test858 \
test859 test860 test861 test862 test863 test864 test865 test866 test867 \
test868 test869 test870 test871 test872 test873 test874 test875 test876 \
test877 test878 test879 test880 test881 test882 test883 test884 test885 \
test886 test887 test888 test889 test890 test891 \
\
test900 test901 test902 test903 test904 test905 test906 test907 test908 \
test909 test910 test911 test912 test913 test914 test915 test916 test917 \
test918 test919 test920 test921 test922 test923 test924 test925 test926 \
test927 test928 test929 test930 test931 test932 test933 test934 test935 \
test936 test937 test938 test939 test940 test941 test942 test943 test944 \
test945 test946 test947 test948 test949 test950 test951 test952 \
\
test1000 test1001 test1002 test1003 test1004 test1005 test1006 test1007 \
test1008 test1009 test1010 test1011 test1012 test1013 test1014 test1015 \
test1016 test1017 test1018 test1019 test1020 test1021 test1022 test1023 \
test1024 test1025 test1026 test1027 test1028 test1029 test1030 test1031 \
test1032 test1033 test1034 test1035 test1036 test1037 test1038 test1039 \
test1040 test1041 test1042 test1043 test1044 test1045 test1046 test1047 \
test1048 test1049 test1050 test1051 test1052 test1053 test1054 test1055 \
test1056 test1057 test1058 test1059 test1060 test1061 test1062 test1063 \
test1064 test1065 test1066 test1067 test1068 test1069 test1070 test1071 \
test1072 test1073 test1074 test1075 test1076 test1077 test1078 test1079 \
test1080 test1081 test1082 test1083 test1084 test1085 test1086 test1087 \
test1088 test1089 test1090 test1091 test1092 test1093 test1094 test1095 \
test1096 test1097 test1098 test1099 test1100 test1101 test1102 test1103 \
test1104 test1105 test1106 test1107 test1108 test1109 test1110 test1111 \
test1112 test1113 test1114 test1115 test1116 test1117 test1118 test1119 \
test1120 test1121 test1122 test1123 test1124 test1125 test1126 test1127 \
test1128 test1129 test1130 test1131 test1132 test1133 test1134 test1135 \
test1136 test1137 test1138 test1139 test1140 test1141 test1142 test1143 \
test1144 test1145 test1146 test1147 test1148 test1149 test1150 test1151 \
test1152 test1153 test1154 test1155 \
\
test1160 test1161 test1162 test1163 test1164 \
test1170 test1171 \
test1200 test1201 test1202 test1203 test1204 test1205 test1206 test1207 \
test1208 test1209 test1210 test1211 test1212 test1213 test1214 test1215 \
test1216 test1217 test1218 test1219 \
test1220 test1221 test1222 test1223 test1224 test1225 test1226 test1227 \
test1228 test1229 test1230 test1231 test1232 test1233 test1234 test1235 \
test1236 test1237 test1238 test1239 test1240 test1241 test1242 test1243 \
test1244 test1245 test1246 test1247 test1248 test1249 test1250 test1251 \
test1252 test1253 test1254 test1255 test1256 test1257 test1258 test1259 \
test1260 test1261 test1262 test1263 test1264 test1265 \
\
test1280 test1281 test1282 test1283 test1284 test1285 test1286 test1287 \
test1288 test1289 test1290 test1291 test1292 \
test1298 test1299 \
test1300 test1301 test1302 test1303 test1304 test1305 test1306 test1307 \
test1308 test1309 test1310 test1311 test1312 test1313 test1314 test1315 \
test1316 test1317 test1318 test1319 test1320 test1321 test1322 test1323 \
test1324 test1325 test1326 test1327 test1328 test1329 test1330 test1331 \
test1332 test1333 test1334 test1335 test1336 test1337 test1338 test1339 \
test1340 test1341 test1342 test1343 test1344 test1345 test1346 test1347 \
test1348 test1349 test1350 test1351 test1352 test1353 test1354 test1355 \
test1356 test1357 test1358 test1359 test1360 test1361 test1362 test1363 \
test1364 test1365 test1366 test1367 test1368 test1369 test1370 test1371 \
test1372 test1373 test1374 test1375 test1376 test1377 test1378 test1379 \
test1380 test1381 test1382 test1383 test1384 test1385 test1386 test1387 \
test1388 test1389 test1390 test1391 test1392 test1393 test1394 test1395 \
test1396 test1397 test1398 test1399 \
\
test1400 test1401 test1402 test1403 test1404 test1405 test1406 test1407 \
test1408 test1409 test1410 test1411 test1412 test1413 test1414 test1415 \
test1416 test1417 test1418 test1419 test1420 test1421 test1422 test1423 \
test1424 test1425 test1426 test1427 \
test1428 test1429 test1430 test1431 test1432 test1433 test1434 test1435 \
test1436 test1437 test1438 test1439 test1440 test1441 test1442 test1443 \
test1444 test1445 test1446 test1447 test1448 test1449 test1450 test1451 \
test1452 test1453 test1454 test1455 test1456 \
test1500 test1501 test1502 test1503 test1504 test1505 test1506 test1507 \
test1508 test1509 test1510 test1511 test1512 test1513 test1514 test1515 \
test1516 test1517 \
\
test1520 test1521 \
\
test1525 test1526 test1527 test1528 test1529 test1530 test1531 test1532 \
test1533 test1534 test1535 test1536 test1537 test1538 \
test1540 \
test1550 test1551 test1552 test1553 test1554 test1555 test1556 \
test1600 test1601 test1602 test1603 test1604 test1605 test1606 test1607 \
test1608 \
\
test1700 test1701 test1702 \
\
test1800 test1801 \
\
test1900 test1901 test1902 test1903 test1904 \
\
test2000 test2001 test2002 test2003 test2004 test2005 test2006 test2007 \
test2008 test2009 test2010 test2011 test2012 test2013 test2014 test2015 \
test2016 test2017 test2018 test2019 test2020 test2021 test2022 test2023 \
test2024 test2025 test2026 test2027 test2028 test2029 test2030 test2031 \
test2032 test2033 test2034 test2035 test2036 test2037 test2038 test2039 \
test2040 test2041 test2042 test2043 test2044 test2045 test2046 test2047 \
test2048 test2049 test2050 test2051 test2052 test2053 test2054 test2055 \
test2056 test2057 test2058 test2059 test2060 test2061 test2062 test2063 \
test2064 test2065 test2066 test2067 test2068 test2069 \
\
test2070 test2071 test2072 test2073 \
\
test3000 test3001
