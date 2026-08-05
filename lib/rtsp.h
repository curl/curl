#ifndef HEADER_CURL_RTSP_H
#define HEADER_CURL_RTSP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifndef CURL_DISABLE_RTSP
CURLcode Curl_rtsp_parseheader(struct Curl_easy *data, const char *header);
extern const struct Curl_protocol Curl_protocol_rtsp;
#else
#define Curl_rtsp_parseheader(x, y) CURLE_NOT_BUILT_IN
#endif

#define RTSPREQ_NONE CURL_RTSPREQ_NONE
#define RTSPREQ_OPTIONS CURL_RTSPREQ_OPTIONS
#define RTSPREQ_DESCRIBE CURL_RTSPREQ_DESCRIBE
#define RTSPREQ_ANNOUNCE CURL_RTSPREQ_ANNOUNCE
#define RTSPREQ_SETUP CURL_RTSPREQ_SETUP
#define RTSPREQ_PLAY CURL_RTSPREQ_PLAY
#define RTSPREQ_PAUSE CURL_RTSPREQ_PAUSE
#define RTSPREQ_TEARDOWN CURL_RTSPREQ_TEARDOWN
#define RTSPREQ_GET_PARAMETER CURL_RTSPREQ_GET_PARAMETER
#define RTSPREQ_SET_PARAMETER CURL_RTSPREQ_SET_PARAMETER
#define RTSPREQ_RECORD CURL_RTSPREQ_RECORD
#define RTSPREQ_RECEIVE CURL_RTSPREQ_RECEIVE
#define RTSPREQ_LAST CURL_RTSPREQ_LAST

#endif /* HEADER_CURL_RTSP_H */
