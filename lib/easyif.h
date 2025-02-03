#ifndef HEADER_FETCH_EASYIF_H
#define HEADER_FETCH_EASYIF_H
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

/*
 * Prototypes for library-wide functions provided by easy.c
 */
FETCHcode Fetch_senddata(struct Fetch_easy *data, const void *buffer,
                        size_t buflen, size_t *n);

#ifndef FETCH_DISABLE_WEBSOCKETS
FETCHcode Fetch_connect_only_attach(struct Fetch_easy *data);
#endif

#ifdef DEBUGBUILD
FETCH_EXTERN FETCHcode fetch_easy_perform_ev(struct Fetch_easy *easy);
#endif

#endif /* HEADER_FETCH_EASYIF_H */
