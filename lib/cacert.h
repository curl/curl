/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*

regenerate this file like so:

curl -Oz cacert.pem https://curl.haxx.se/ca/cacert.pem \
&& xxd -i -C cacert.pem | sed -r 's/(0x..)$/\1, 0x00/' > lib/cacert.h

unless CACERT_PEM is defined in here, there will be a compile error if
CURL_CA_BUNDLE_PEM is defined, CACERT_PEM must be a proper null-terminated
C string

unsigned char CACERT_PEM[] = {
  0x62, 0x6f, 0x62, 0x0a, 0x00
};
unsigned int CACERT_PEM_LEN = 4;
*/
