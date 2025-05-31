#ifndef HEADER_CURL_HTTP_AWS_SIGV4_H
#define HEADER_CURL_HTTP_AWS_SIGV4_H
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
#include "curl_setup.h"
#include "curlx/dynbuf.h"
#include "urldata.h"
#include "curlx/strparse.h"

/* this is for creating aws_sigv4 header output */
CURLcode Curl_output_aws_sigv4(struct Curl_easy *data);

#ifdef UNITTESTS
UNITTEST CURLcode canon_path(const char *q, size_t len,
    struct dynbuf *new_path,
    bool normalize);
UNITTEST CURLcode canon_query(const char *query, struct dynbuf *dq);
#endif

#endif /* HEADER_CURL_HTTP_AWS_SIGV4_H */
