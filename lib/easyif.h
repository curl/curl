#ifndef __EASYIF_H
#define __EASYIF_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

/*
 * Prototypes for library-wide functions provided by easy.c
 */
void Curl_easy_addmulti(struct SessionHandle *data, void *multi);

void Curl_easy_initHandleData(struct SessionHandle *data);

CURLcode Curl_convert_to_network(struct SessionHandle *data,
                                 char *buffer, size_t length);
CURLcode Curl_convert_from_network(struct SessionHandle *data,
                                 char *buffer, size_t length);
CURLcode Curl_convert_from_utf8(struct SessionHandle *data,
                                 char *buffer, size_t length);

#endif /* __EASYIF_H */
