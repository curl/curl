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
#include "dynhds.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static struct dynhds_entry *
entry_new(const char *name, size_t namelen,
          const char *value, size_t valuelen)
{
  struct dynhds_entry *e;
  char *p;

  DEBUGASSERT(name);
  DEBUGASSERT(value);
  e = calloc(1, sizeof(*e) + namelen + valuelen + 2);
  if(!e)
    return NULL;
  e->name = p = ((char *)e) + sizeof(*e);
  memcpy(p, name, namelen);
  e->namelen = namelen;
  e->value = p += namelen + 1; /* leave a \0 at the end of name */
  memcpy(p, value, valuelen);
  e->valuelen = valuelen;
  return e;
}

static void entry_free(struct dynhds_entry *e)
{
  free(e);
}

void Curl_dynhds_init(struct dynhds *dynhds, size_t max_entries,
                      size_t max_strs_size)
{
  DEBUGASSERT(dynhds);
  DEBUGASSERT(max_strs_size);
  dynhds->hds = NULL;
  dynhds->hds_len = dynhds->hds_allc = dynhds->strs_len = 0;
  dynhds->max_entries = max_entries;
  dynhds->max_strs_size = max_strs_size;
}

void Curl_dynhds_free(struct dynhds *dynhds)
{
  DEBUGASSERT(dynhds);
  if(dynhds->hds && dynhds->hds_len) {
    size_t i;
    DEBUGASSERT(dynhds->hds);
    for(i = 0; i < dynhds->hds_len; ++i) {
      entry_free(dynhds->hds[i]);
    }
  }
  Curl_safefree(dynhds->hds);
  dynhds->hds_len = dynhds->hds_allc = dynhds->strs_len = 0;
}

void Curl_dynhds_reset(struct dynhds *dynhds)
{
  DEBUGASSERT(dynhds);
  if(dynhds->hds_len) {
    size_t i;
    DEBUGASSERT(dynhds->hds);
    for(i = 0; i < dynhds->hds_len; ++i) {
      entry_free(dynhds->hds[i]);
      dynhds->hds[i] = NULL;
    }
  }
  dynhds->hds_len = dynhds->strs_len = 0;
}

size_t Curl_dynhds_count(struct dynhds *dynhds)
{
  return dynhds->hds_len;
}

struct dynhds_entry *Curl_dynhds_getn(struct dynhds *dynhds, size_t n)
{
  DEBUGASSERT(dynhds);
  return (n < dynhds->hds_len)? dynhds->hds[n] : NULL;
}

struct dynhds_entry *Curl_dynhds_get(struct dynhds *dynhds, const char *name,
                                     size_t namelen)
{
  size_t i;
  for(i = 0; i < dynhds->hds_len; ++i) {
    if(dynhds->hds[i]->namelen == namelen &&
       strncasecompare(dynhds->hds[i]->name, name, namelen)) {
      return dynhds->hds[i];
    }
  }
  return NULL;
}

struct dynhds_entry *Curl_dynhds_cget(struct dynhds *dynhds, const char *name)
{
  return Curl_dynhds_get(dynhds, name, strlen(name));
}

bool Curl_dynhds_contains(struct dynhds *dynhds,
                          const char *name, size_t namelen)
{
  return !!Curl_dynhds_get(dynhds, name, namelen);
}

bool Curl_dynhds_ccontains(struct dynhds *dynhds, const char *name)
{
  return Curl_dynhds_contains(dynhds, name, strlen(name));
}

CURLcode Curl_dynhds_add(struct dynhds *dynhds,
                         const char *name, size_t namelen,
                         const char *value, size_t valuelen)
{
  struct dynhds_entry *entry = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(dynhds);
  if(dynhds->max_entries && dynhds->hds_len >= dynhds->max_entries)
    return CURLE_OUT_OF_MEMORY;
  if(dynhds->strs_len + namelen + valuelen > dynhds->max_strs_size)
    return CURLE_OUT_OF_MEMORY;

  entry = entry_new(name, namelen, value, valuelen);
  if(!entry)
    goto out;

  if(dynhds->hds_len + 1 >= dynhds->hds_allc) {
    size_t nallc = dynhds->hds_len + 16;
    struct dynhds_entry **nhds;

    if(dynhds->max_entries && nallc > dynhds->max_entries)
      nallc = dynhds->max_entries;

    nhds = calloc(nallc, sizeof(struct dynhds_entry *));
    if(!nhds)
      goto out;
    if(dynhds->hds) {
      memcpy(nhds, dynhds->hds,
             dynhds->hds_len * sizeof(struct dynhds_entry *));
      Curl_safefree(dynhds->hds);
    }
    dynhds->hds = nhds;
    dynhds->hds_allc = nallc;
  }
  dynhds->hds[dynhds->hds_len++] = entry;
  entry = NULL;
  dynhds->strs_len += namelen + valuelen;
  result = CURLE_OK;

out:
  if(entry)
    entry_free(entry);
  return result;
}

CURLcode Curl_dynhds_cadd(struct dynhds *dynhds,
                          const char *name, const char *value)
{
  return Curl_dynhds_add(dynhds, name, strlen(name), value, strlen(value));
}

CURLcode Curl_dynhds_set(struct dynhds *dynhds,
                         const char *name, size_t namelen,
                         const char *value, size_t valuelen)
{
  Curl_dynhds_remove(dynhds, name, namelen);
  return Curl_dynhds_add(dynhds, name, namelen, value, valuelen);
}

CURLcode Curl_dynhds_cset(struct dynhds *dynhds,
                          const char *name, const char *value)
{
  return Curl_dynhds_set(dynhds, name, strlen(name), value, strlen(value));
}

CURLcode Curl_dynhds_h1_cadd_line(struct dynhds *dynhds, const char *line)
{
  const char *p;
  const char *name;
  size_t namelen;
  const char *value;
  size_t valuelen;

  if(!line)
    return CURLE_OK;
  p = strchr(line, ':');
  if(!p) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  name = line;
  namelen = p - line;
  p++; /* move past the colon */
  while(ISBLANK(*p))
    p++;
  value = p;
  p = strchr(value, '\r');
  if(!p)
    p = strchr(value, '\n');
  valuelen = p? ((size_t)(p - value)) : strlen(value);

  return Curl_dynhds_add(dynhds, name, namelen, value, valuelen);
}

size_t Curl_dynhds_count_name(struct dynhds *dynhds,
                              const char *name, size_t namelen)
{
  size_t n = 0;
  if(dynhds->hds_len) {
    size_t i;
    for(i = 0; i < dynhds->hds_len; ++i) {
      if((namelen == dynhds->hds[i]->namelen) &&
         strncasecompare(name, dynhds->hds[i]->name, namelen))
         ++n;
    }
  }
  return n;
}

size_t Curl_dynhds_ccount_name(struct dynhds *dynhds, const char *name)
{
  return Curl_dynhds_count_name(dynhds, name, strlen(name));
}

size_t Curl_dynhds_remove(struct dynhds *dynhds,
                          const char *name, size_t namelen)
{
  size_t n = 0;
  if(dynhds->hds_len) {
    size_t i, len;
    for(i = 0; i < dynhds->hds_len; ++i) {
      if((namelen == dynhds->hds[i]->namelen) &&
         strncasecompare(name, dynhds->hds[i]->name, namelen)) {
        ++n;
        --dynhds->hds_len;
        dynhds->strs_len -= (dynhds->hds[i]->namelen +
                             dynhds->hds[i]->valuelen);
        entry_free(dynhds->hds[i]);
        len = dynhds->hds_len - i; /* remaining entries */
        if(len) {
          memmove(&dynhds->hds[i], &dynhds->hds[i + 1],
                  len * sizeof(dynhds->hds[i]));
        }
        --i; /* do this index again */
      }
    }
  }
  return n;
}

size_t Curl_dynhds_cremove(struct dynhds *dynhds, const char *name)
{
  return Curl_dynhds_remove(dynhds, name, strlen(name));
}

CURLcode Curl_dynhds_h1_dprint(struct dynhds *dynhds, struct dynbuf *dbuf)
{
  CURLcode result = CURLE_OK;
  size_t i;

  if(!dynhds->hds_len)
    return result;

  for(i = 0; i < dynhds->hds_len; ++i) {
    result = Curl_dyn_addf(dbuf, "%.*s: %.*s\r\n",
               (int)dynhds->hds[i]->namelen, dynhds->hds[i]->name,
               (int)dynhds->hds[i]->valuelen, dynhds->hds[i]->value);
    if(result)
      break;
  }

  return result;
}
