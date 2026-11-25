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

#include "frzn_strs.h"

void Curl_frzn_strs_free(struct Curl_frzn_strs *fstrs)
{
  curlx_free(fstrs);
}

void Curl_frzn_strs_safefree(struct Curl_frzn_strs **pfstrs)
{
  curlx_safefree(*pfstrs);
}

struct Curl_frzn_strs *Curl_frzn_strs_from_slist(struct curl_slist *src)
{
  struct curl_slist *l;
  struct Curl_frzn_strs *fstrs = NULL;
  size_t n = 0;
  size_t all_str_lens = 0, meta_len;
  char *cdest;

  if(!src)
    return NULL;

  for(l = src; l; l = l->next) {
    size_t slen = (l->data ? strlen(l->data) : 0) + 1; /* incl. 0 byte */
    if((SIZE_MAX - slen) <= all_str_lens)
      return NULL;
    ++n;
    all_str_lens += slen;
  }

  if(n > UINT32_MAX)
    return NULL;
  meta_len = sizeof(*fstrs) + (n ? ((n - 1) * sizeof(struct Curl_str)) : 0);
  if((SIZE_MAX - all_str_lens) <= meta_len)
    return NULL;

  fstrs = curlx_calloc(1, meta_len + all_str_lens);
  if(!fstrs)
    return NULL;

  fstrs->strs = &fstrs->s;
  fstrs->n = n;
  cdest = (char *)fstrs + meta_len;
  for(l = src, n = 0; l && (n < fstrs->n); l = l->next, ++n) {
    size_t slen = (l->data ? strlen(l->data) : 0);
    fstrs->strs[n].str = cdest;
    fstrs->strs[n].len = slen;
    if(slen) {
      memcpy(cdest, l->data, slen);
      cdest += slen;
    }
    *cdest++ = '\0';
  }

  return fstrs;
}

struct Curl_frzn_strs *Curl_frzn_strs_dup(struct Curl_frzn_strs *src)
{
  struct Curl_frzn_strs *fstrs;
  size_t idx, n = Curl_frzn_strs_count(src);
  size_t all_str_lens = 0, meta_len;
  const char *s;
  char *cdest;
  size_t slen;

  if(!src)
    return NULL;

  for(idx = 0; idx < n; ++idx) {
    slen = Curl_frzn_strs_get_len(src, idx);
    all_str_lens += slen + 1; /* incl. 0 */
  }

  meta_len = sizeof(*fstrs) + (n ? ((n - 1) * sizeof(struct Curl_str)) : 0);
  fstrs = curlx_calloc(1, meta_len + all_str_lens);
  if(!fstrs)
    return NULL;

  fstrs->strs = &fstrs->s;
  fstrs->n = n;
  cdest = (char *)fstrs + meta_len;
  for(idx = 0; idx < n; ++idx) {
    s = Curl_frzn_strs_get_str(src, idx);
    slen = Curl_frzn_strs_get_len(src, idx);
    fstrs->strs[idx].str = cdest;
    fstrs->strs[idx].len = slen;
    if(slen) {
      memcpy(cdest, s, slen);
      cdest += slen;
    }
    *cdest++ = '\0';
  }

  return fstrs;
}
