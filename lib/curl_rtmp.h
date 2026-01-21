#ifndef HEADER_CURL_RTMP_H
#define HEADER_CURL_RTMP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Howard Chu, <hyc@highlandsun.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
extern const struct Curl_scheme Curl_scheme_rtmp;
extern const struct Curl_scheme Curl_scheme_rtmpt;
extern const struct Curl_scheme Curl_scheme_rtmpe;
extern const struct Curl_scheme Curl_scheme_rtmpte;
extern const struct Curl_scheme Curl_scheme_rtmps;
extern const struct Curl_scheme Curl_scheme_rtmpts;
#ifdef USE_LIBRTMP
void Curl_rtmp_version(char *version, size_t len);
#endif

#endif /* HEADER_CURL_RTMP_H */
