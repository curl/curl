#ifndef HEADER_CURL_STRTOOFFT_H
#define HEADER_CURL_STRTOOFFT_H
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
#include "strparse.h"

typedef enum {
  CURL_OFFT_OK,    /* parsed fine */
  CURL_OFFT_FLOW,  /* over or underflow */
  CURL_OFFT_INVAL  /* nothing was parsed */
} CURLofft;

CURLofft curlx_strtoofft(const char *str, char **endp, int base,
                         curl_off_t *num);

#endif /* HEADER_CURL_STRTOOFFT_H */
