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
#include "easyoptions.h"

#ifndef CURL_DISABLE_GETOPTIONS

/* Lookups easy options at runtime */
static const struct curl_easyoption *lookup(const char *name, CURLoption id)
{
  DEBUGASSERT(name || id);
  DEBUGASSERT(!Curl_easyopts_check());
  if(name || id) {
    const struct curl_easyoption *o = &Curl_easyopts[0];
    do {
      if(name) {
        if(curl_strequal(o->name, name))
          return o;
      }
      else {
        if((o->id == id) && !(o->flags & CURLOT_FLAG_ALIAS))
          /* do not match alias options */
          return o;
      }
      o++;
    } while(o->name);
  }
  return NULL;
}

const struct curl_easyoption *curl_easy_option_by_name(const char *name)
{
  /* when name is used, the id argument is ignored */
  return lookup(name, CURLOPT_LASTENTRY);
}

const struct curl_easyoption *curl_easy_option_by_id(CURLoption id)
{
  return lookup(NULL, id);
}

/* Iterates over available options */
const struct curl_easyoption *
curl_easy_option_next(const struct curl_easyoption *prev)
{
  if(prev && prev->name) {
    prev++;
    if(prev->name)
      return prev;
  }
  else if(!prev)
    return &Curl_easyopts[0];
  return NULL;
}

#else
const struct curl_easyoption *curl_easy_option_by_name(const char *name)
{
  (void)name;
  return NULL;
}

const struct curl_easyoption *curl_easy_option_by_id (CURLoption id)
{
  (void)id;
  return NULL;
}

const struct curl_easyoption *
curl_easy_option_next(const struct curl_easyoption *prev)
{
  (void)prev;
  return NULL;
}
#endif
