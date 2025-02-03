#ifndef HEADER_FETCH_MD4_H
#define HEADER_FETCH_MD4_H
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

#include "fetch_setup.h"
#include <fetch/fetch.h>

#if defined(USE_FETCH_NTLM_CORE)

#define MD4_DIGEST_LENGTH 16

FETCHcode Fetch_md4it(unsigned char *output, const unsigned char *input,
                     const size_t len);

#endif /* defined(USE_FETCH_NTLM_CORE) */

#endif /* HEADER_FETCH_MD4_H */
