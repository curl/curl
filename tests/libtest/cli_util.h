#ifndef HEADER_CLI_UTIL_H
#define HEADER_CLI_UTIL_H
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
#include "first.h"

/* callback for CURLOPT_DEBUGFUNCTION (used in client tests) */
int cli_debug_cb(CURL *handle, curl_infotype type,
                 char *data, size_t size, void *userp);

#ifndef CURL_DISABLE_WEBSOCKETS
/* just close the connection */
void websocket_close(CURL *curl);
#endif

extern int coptind;
extern const char *coptarg;

int cgetopt(int argc, const char * const argv[], const char *optstring);

#endif /* HEADER_CLI_UTIL_H */
