#ifndef HEADER_CURL_SERVER_GETPART_H
#define HEADER_CURL_SERVER_GETPART_H
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
#include "server_setup.h"

#include "strdup.h"

#define GPE_NO_BUFFER_SPACE -2
#define GPE_OUT_OF_MEMORY   -1
#define GPE_OK               0
#define GPE_END_OF_FILE      1

int getpart(char **outbuf, size_t *outlen,
            const char *main, const char *sub, FILE *stream);

#endif /* HEADER_CURL_SERVER_GETPART_H */
