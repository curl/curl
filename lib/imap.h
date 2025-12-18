#ifndef HEADER_CURL_IMAP_H
#define HEADER_CURL_IMAP_H
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

#include "pingpong.h"
#include "curl_sasl.h"


extern const struct Curl_handler Curl_handler_imap;
extern const struct Curl_handler Curl_handler_imaps;

/* Authentication type flags */
#define IMAP_TYPE_CLEARTEXT (1 << 0)
#define IMAP_TYPE_SASL      (1 << 1)

/* Authentication type values */
#define IMAP_TYPE_NONE      0
#define IMAP_TYPE_ANY       (IMAP_TYPE_CLEARTEXT|IMAP_TYPE_SASL)

#endif /* HEADER_CURL_IMAP_H */
