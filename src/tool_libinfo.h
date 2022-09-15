#ifndef HEADER_CURL_TOOL_LIBINFO_H
#define HEADER_CURL_TOOL_LIBINFO_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

/* global variable declarations, for libcurl run-time info */

typedef unsigned int proto_t;   /* A protocol number.*/

#define PROTO_NONE ((proto_t) -1)

/* Protocol numbers set type. This should have enough bits for all
 * enabled protocols.
 */
typedef unsigned int proto_set_t;

#define PROTO_MAX       ((proto_t) (8 * sizeof(proto_set_t)))

#define PROTO_BIT(p)    ((p) < PROTO_MAX? (proto_set_t) 1 << (p):       \
                                          (proto_set_t) 0)

#define PROTO_ALL       (PROTO_BIT(proto_last) - (proto_set_t) 1)


extern curl_version_info_data *curlinfo;
extern proto_t proto_last;

extern proto_t proto_ftp;
extern proto_t proto_ftps;
extern proto_t proto_http;
extern proto_t proto_https;
extern proto_t proto_file;
extern proto_t proto_rtsp;
extern proto_t proto_scp;
extern proto_t proto_sftp;
extern proto_t proto_tftp;

CURLcode get_libcurl_info(void);
proto_t scheme2protocol(const char *scheme);
const char *protocol2scheme(proto_t proto);

#endif /* HEADER_CURL_TOOL_LIBINFO_H */
