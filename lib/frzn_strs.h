#ifndef HEADER_CURL_FRZN_STRS_H
#define HEADER_CURL_FRZN_STRS_H
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

#include "curlx/strparse.h"

struct Curl_frzn_strs {
  struct Curl_str *strs;
  size_t n;
  /* pointers and the characters themselves allocated
   * together with this struct. */
  struct Curl_str s;
};

#define Curl_frzn_strs_count(fstrs) \
  ((fstrs) ? (fstrs)->n : 0)

#define Curl_frzn_strs_get(fstrs, idx) \
  (((idx) < (fstrs)->n) ? &(fstrs)->strs[(idx)] : NULL)
#define Curl_frzn_strs_get_str(fstrs, idx) \
  (((idx) < (fstrs)->n) ? (fstrs)->strs[(idx)].str : NULL)
#define Curl_frzn_strs_get_len(fstrs, idx) \
  (((idx) < (fstrs)->n) ? (fstrs)->strs[(idx)].len : 0)

void Curl_frzn_strs_free(struct Curl_frzn_strs *fstrs);
void Curl_frzn_strs_safefree(struct Curl_frzn_strs **pfstrs);

struct Curl_frzn_strs *Curl_frzn_strs_from_slist(struct curl_slist *src);

struct Curl_frzn_strs *Curl_frzn_strs_dup(struct Curl_frzn_strs *src);


#endif /* HEADER_CURL_FRZN_STRS_H */
