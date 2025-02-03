#ifndef HEADER_FETCH_GET_LINE_H
#define HEADER_FETCH_GET_LINE_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "dynbuf.h"

#ifndef BUILDING_LIBFETCH
/* this renames functions so that the tool code can use the same code
   without getting symbol collisions */
#define Curl_get_line(a,b) fetchx_get_line(a,b)
#endif

/* Curl_get_line() returns complete lines that end with a newline. */
int Curl_get_line(struct dynbuf *buf, FILE *input);

#endif /* HEADER_FETCH_GET_LINE_H */
