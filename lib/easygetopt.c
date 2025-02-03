/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ | |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             ___|___/|_| ______|
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"
#include "strcase.h"
#include "easyoptions.h"

#ifndef FETCH_DISABLE_GETOPTIONS

/* Lookups easy options at runtime */
static struct fetch_easyoption *lookup(const char *name, FETCHoption id)
{
  DEBUGASSERT(name || id);
  DEBUGASSERT(!Curl_easyopts_check());
  if (name || id)
  {
    struct fetch_easyoption *o = &Curl_easyopts[0];
    do
    {
      if (name)
      {
        if (strcasecompare(o->name, name))
          return o;
      }
      else
      {
        if ((o->id == id) && !(o->flags & FETCHOT_FLAG_ALIAS))
          /* do not match alias options */
          return o;
      }
      o++;
    } while (o->name);
  }
  return NULL;
}

const struct fetch_easyoption *fetch_easy_option_by_name(const char *name)
{
  /* when name is used, the id argument is ignored */
  return lookup(name, FETCHOPT_LASTENTRY);
}

const struct fetch_easyoption *fetch_easy_option_by_id(FETCHoption id)
{
  return lookup(NULL, id);
}

/* Iterates over available options */
const struct fetch_easyoption *
fetch_easy_option_next(const struct fetch_easyoption *prev)
{
  if (prev && prev->name)
  {
    prev++;
    if (prev->name)
      return prev;
  }
  else if (!prev)
    return &Curl_easyopts[0];
  return NULL;
}

#else
const struct fetch_easyoption *fetch_easy_option_by_name(const char *name)
{
  (void)name;
  return NULL;
}

const struct fetch_easyoption *fetch_easy_option_by_id(FETCHoption id)
{
  (void)id;
  return NULL;
}

const struct fetch_easyoption *
fetch_easy_option_next(const struct fetch_easyoption *prev)
{
  (void)prev;
  return NULL;
}
#endif
