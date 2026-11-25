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
#include "curlx/strparse.h"

static struct dynhds_entry *entry_new(const char *name, uint32_t namelen,
                                      const char *value, uint32_t valuelen,
                                      uint8_t opts)
{
  struct dynhds_entry *e;
  char *p;

  /* namelen + valuelen <= SIZE_MAX has already been checked by caller */
  if((SIZE_MAX - namelen - valuelen) < (sizeof(*e) + 2))
    return NULL;
  e = curlx_calloc(1, sizeof(*e) + namelen + valuelen + 2);
  if(!e)
    return NULL;
  e->name = p = (char *)e + sizeof(*e);
  memcpy(p, name, namelen);
  e->namelen = namelen;
  e->value = p += namelen + 1; /* leave a \0 at the end of name */
  if(valuelen) {
    memcpy(p, value, valuelen);
    e->valuelen = valuelen;
  }
  if(opts & DYNHDS_OPT_LOWERCASE)
    Curl_strntolower(e->name, e->name, e->namelen);
  return e;
}

static void entry_free(struct dynhds_entry *e)
{
  curlx_free(e);
}

void Curl_dynhds_init(struct dynhds *dynhds, uint32_t max_entries,
                      uint32_t max_strs_size)
{
  DEBUGASSERT(dynhds);
  dynhds->hds = NULL;
  dynhds->hds_len = dynhds->hds_allc = dynhds->strs_len = 0;
  dynhds->max_entries = max_entries ? max_entries : UINT32_MAX;
  dynhds->max_strs_size = max_strs_size ? max_strs_size : UINT32_MAX;
  dynhds->opts = 0;
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

void Curl_dynhds_cleanup(struct dynhds *dynhds)
{
  DEBUGASSERT(dynhds);
  Curl_dynhds_reset(dynhds);
  curlx_safefree(dynhds->hds);
  dynhds->hds_allc = 0;
}

uint32_t Curl_dynhds_count(struct dynhds *dynhds)
{
  return dynhds->hds_len;
}

void Curl_dynhds_set_opts(struct dynhds *dynhds, uint8_t opts)
{
  dynhds->opts = opts;
}

struct dynhds_entry *Curl_dynhds_getn(struct dynhds *dynhds, uint32_t n)
{
  DEBUGASSERT(dynhds);
  return (n < dynhds->hds_len) ? dynhds->hds[n] : NULL;
}

struct dynhds_entry *Curl_dynhds_get(struct dynhds *dynhds, const char *name,
                                     size_t namelen)
{
  size_t i;
  for(i = 0; i < dynhds->hds_len; ++i) {
    if(dynhds->hds[i]->namelen == namelen &&
       curl_strnequal(dynhds->hds[i]->name, name, namelen)) {
      return dynhds->hds[i];
    }
  }
  return NULL;
}

struct dynhds_entry *Curl_dynhds_cget(struct dynhds *dynhds, const char *name)
{
  return Curl_dynhds_get(dynhds, name, strlen(name));
}

CURLcode Curl_dynhds_add(struct dynhds *dynhds,
                         const char *name, size_t namelen,
                         const char *value, size_t valuelen)
{
  struct dynhds_entry *entry = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  uint32_t nlen, vlen;

  /* Accept NULL value with length 0, name must have length */
  if(!dynhds || !name || !namelen || (!value && valuelen)) {
    DEBUGASSERT(0);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if((namelen > UINT32_MAX) || (valuelen > UINT32_MAX))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  nlen = (uint32_t)namelen;
  vlen = (uint32_t)valuelen;

  /* Does the new header fit into the limits? */
  if((dynhds->hds_len >= dynhds->max_entries) ||
     (dynhds->max_strs_size - dynhds->strs_len < nlen) ||
     (dynhds->max_strs_size - dynhds->strs_len - nlen < vlen))
    return CURLE_OUT_OF_MEMORY;

  entry = entry_new(name, nlen, value, vlen, dynhds->opts);
  if(!entry)
    goto out;

  if((dynhds->hds_allc - dynhds->hds_len) < 1) {
    struct dynhds_entry **nhds;
    uint32_t nhds_allc;

    /* start with room for 16 headers, then double, add max 512 new ones
     * or what the limit still allows. */
    if(dynhds->hds_allc) {
      uint32_t max_grow =
        CURLMIN(dynhds->max_entries - dynhds->hds_allc, 512);
      nhds_allc = dynhds->hds_allc + CURLMIN(dynhds->hds_allc, max_grow);
    }
    else
      nhds_allc = 16;

    nhds = curlx_calloc(nhds_allc, sizeof(struct dynhds_entry *));
    if(!nhds)
      goto out;
    if(dynhds->hds) {
      memcpy(nhds, dynhds->hds,
             dynhds->hds_len * sizeof(struct dynhds_entry *));
      curlx_safefree(dynhds->hds);
    }
    dynhds->hds = nhds;
    dynhds->hds_allc = nhds_allc;
  }
  dynhds->hds[dynhds->hds_len++] = entry;
  entry = NULL;
  dynhds->strs_len += nlen + vlen;
  result = CURLE_OK;

out:
  if(entry)
    entry_free(entry);
  return result;
}

CURLcode Curl_dynhds_cadd(struct dynhds *dynhds,
                          const char *name, const char *value)
{
  if(!name)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return Curl_dynhds_add(dynhds, name, strlen(name),
                         value, value ? strlen(value) : 0);
}

CURLcode Curl_dynhds_h1_add_line(struct dynhds *dynhds,
                                 const char *line, size_t line_len)
{
  const char *p;
  const char *name;
  size_t namelen;
  const char *value;
  size_t valuelen, i;

  if(!line || !line_len)
    return CURLE_OK;

  p = memchr(line, ':', line_len);
  if(!p || p == line)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  name = line;
  namelen = p - line;
  p++; /* move past the colon */
  for(i = namelen + 1; i < line_len; ++i, ++p) {
    if(!ISBLANK(*p))
      break;
  }
  value = p;
  valuelen = line_len - i;

  p = memchr(value, '\r', valuelen);
  if(!p)
    p = memchr(value, '\n', valuelen);
  if(p)
    valuelen = (size_t)(p - value);

  return Curl_dynhds_add(dynhds, name, namelen, value, valuelen);
}

CURLcode Curl_dynhds_h1_cadd_line(struct dynhds *dynhds, const char *line)
{
  return Curl_dynhds_h1_add_line(dynhds, line, line ? strlen(line) : 0);
}

#ifdef UNITTESTS
/* @unittest 2602 */

/**
 * Return TRUE iff one or more headers with the given name exist.
 */
UNITTEST bool dynhds_contains(struct dynhds *dynhds,
                              const char *name, size_t namelen);
UNITTEST bool dynhds_contains(struct dynhds *dynhds,
                              const char *name, size_t namelen)
{
  return !!Curl_dynhds_get(dynhds, name, namelen);
}

/* @unittest 2602 */
UNITTEST bool dynhds_ccontains(struct dynhds *dynhds, const char *name);
UNITTEST bool dynhds_ccontains(struct dynhds *dynhds, const char *name)
{
  return dynhds_contains(dynhds, name, strlen(name));
}

/**
 * Return how often the given name appears in `dynhds`.
 * Names are case-insensitive.
 *
 * @unittest 2602
 */
UNITTEST size_t dynhds_count_name(struct dynhds *dynhds,
                                  const char *name, size_t namelen);
UNITTEST size_t dynhds_count_name(struct dynhds *dynhds,
                                  const char *name, size_t namelen)
{
  size_t n = 0;
  if(dynhds->hds_len) {
    size_t i;
    for(i = 0; i < dynhds->hds_len; ++i) {
      if((namelen == dynhds->hds[i]->namelen) &&
         curl_strnequal(name, dynhds->hds[i]->name, namelen))
        ++n;
    }
  }
  return n;
}

/**
 * Return how often the given null-terminated name appears in `dynhds`.
 * Names are case-insensitive.
 *
 * @unittest 2602
 */
UNITTEST size_t dynhds_ccount_name(struct dynhds *dynhds,
                                        const char *name);
UNITTEST size_t dynhds_ccount_name(struct dynhds *dynhds,
                                        const char *name)
{
  return dynhds_count_name(dynhds, name, strlen(name));
}

/**
 * Remove all entries with the given name.
 * Returns number of entries removed.
 *
 * @unittest 2602
 */
UNITTEST size_t dynhds_remove(struct dynhds *dynhds,
                              const char *name, size_t namelen);
UNITTEST size_t dynhds_remove(struct dynhds *dynhds,
                              const char *name, size_t namelen)
{
  size_t n = 0;
  if(dynhds->hds_len) {
    size_t i, len;
    for(i = 0; i < dynhds->hds_len; ++i) {
      if((namelen == dynhds->hds[i]->namelen) &&
         curl_strnequal(name, dynhds->hds[i]->name, namelen)) {
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

/**
 * Set the give header name and value, replacing any entries with
 * the same name. The header is added at the end of all (remaining)
 * entries.
 *
 * @unittest 2602
 */
UNITTEST CURLcode dynhds_set(struct dynhds *dynhds,
                             const char *name, size_t namelen,
                             const char *value, size_t valuelen);
UNITTEST CURLcode dynhds_set(struct dynhds *dynhds,
                             const char *name, size_t namelen,
                             const char *value, size_t valuelen)
{
  dynhds_remove(dynhds, name, namelen);
  return Curl_dynhds_add(dynhds, name, namelen, value, valuelen);
}

/* @unittest 2602 */
UNITTEST size_t dynhds_cremove(struct dynhds *dynhds, const char *name);
UNITTEST size_t dynhds_cremove(struct dynhds *dynhds, const char *name)
{
  return dynhds_remove(dynhds, name, strlen(name));
}

#endif /* UNITTESTS */

CURLcode Curl_dynhds_h1_dprint(struct dynhds *dynhds, struct dynbuf *dbuf)
{
  CURLcode result = CURLE_OK;
  size_t i;

  if(!dynhds->hds_len)
    return result;

  for(i = 0; i < dynhds->hds_len; ++i) {
    result = curlx_dyn_addn(dbuf, dynhds->hds[i]->name,
                            dynhds->hds[i]->namelen);
    if(!result)
      result = curlx_dyn_addn(dbuf, STRCONST(": "));
    if(!result)
      result = curlx_dyn_addn(dbuf, dynhds->hds[i]->value,
                              dynhds->hds[i]->valuelen);
    if(!result)
      result = curlx_dyn_addn(dbuf, STRCONST("\r\n"));
    if(result)
      break;
  }

  return result;
}

CURLcode Curl_dynhds_add_slist(struct dynhds *dynhds,
                               struct curl_slist *headers,
                               Curl_dynhds_hd_cb *hd_cb,
                               void *user_data)
{
  CURLcode result;

  for(; headers; headers = headers->next) {
    struct Curl_str name, value;
    const char *ptr = headers->data;
    size_t hlen = strlen(headers->data);

    value.str = NULL;
    value.len = 0;
    /* There are 2 quirks in place for custom headers:
     * 1. setting only 'name:' to suppress a header from being sent
     * 2. setting only 'name;' to send an empty (illegal) header
     */
    if(!curlx_str_until(&ptr, &name, hlen, ';') &&
       !curlx_str_single(&ptr, ';') &&
       !curlx_str_single(&ptr, '\0') &&
       !memchr(curlx_str(&name), ':', curlx_strlen(&name))) {
      /* quirk #2, send an empty header */
      value.str = "";
      value.len = 0;
    }
    else {
      ptr = headers->data;
      if(!curlx_str_until(&ptr, &name, hlen, ':') &&
         !curlx_str_single(&ptr, ':')) {
        curlx_str_untilnl(&ptr, &value, hlen);
        curlx_str_trimblanks(&value);
        if(!curlx_strlen(&value))
          /* quirk #1, do not send this */
          continue;
      }
      else
        /* no colon */
        continue;
    }

    DEBUGASSERT(curlx_strlen(&name) && value.str);
    /* trim surrounding whitespace so a padded field name to
     * prevent the name form passing checks */
    curlx_str_trimblanks(&name);
    if(!curlx_strlen(&name))
      continue;

    if(hd_cb) {
      result = hd_cb(user_data, &name, &value, headers->data);
      if(result == CURLE_AGAIN)
        continue;
      else if(result)
        return result;
    }

    if(dynhds) {
      result = Curl_dynhds_add(dynhds, curlx_str(&name), curlx_strlen(&name),
                               curlx_str(&value), curlx_strlen(&value));
      if(result)
        return result;
    }
  }
  return CURLE_OK;
}

#ifdef USE_NGHTTP2

nghttp2_nv *Curl_dynhds_to_nva(struct dynhds *dynhds, size_t *pcount)
{
  nghttp2_nv *nva = curlx_calloc(1, sizeof(nghttp2_nv) * dynhds->hds_len);
  size_t i;

  *pcount = 0;
  if(!nva)
    return NULL;

  for(i = 0; i < dynhds->hds_len; ++i) {
    struct dynhds_entry *e = dynhds->hds[i];
    DEBUGASSERT(e);
    nva[i].name = (unsigned char *)e->name;
    nva[i].namelen = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].valuelen = e->valuelen;
    nva[i].flags = NGHTTP2_NV_FLAG_NONE;
  }
  *pcount = dynhds->hds_len;
  return nva;
}

#endif /* USE_NGHTTP2 */
