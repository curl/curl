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

#include "urldata.h"
#include "strdup.h"
#include "strcase.h"
#include "headers.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HEADERS_API)

/* Generate the curl_header struct for the user. This function MUST assign all
   struct fields in the output struct. */
static void copy_header_external(struct Curl_header_store *hs,
                                 size_t index,
                                 size_t amount,
                                 struct Curl_llist_element *e,
                                 struct curl_header *hout)
{
  struct curl_header *h = hout;
  h->name = hs->name;
  h->value = hs->value;
  h->amount = amount;
  h->index = index;
  /* this will randomly OR a reserved bit for the sole purpose of making it
     impossible for applications to do == comparisons, as that would otherwise
     be very tempting and then lead to the reserved bits not being reserved
     anymore. */
  h->origin = hs->type | (1<<27);
  h->anchor = e;
}

/* public API */
CURLHcode curl_easy_header(CURL *easy,
                           const char *name,
                           size_t nameindex,
                           unsigned int type,
                           int request,
                           struct curl_header **hout)
{
  struct Curl_llist_element *e;
  struct Curl_llist_element *e_pick = NULL;
  struct Curl_easy *data = easy;
  size_t match = 0;
  size_t amount = 0;
  struct Curl_header_store *hs = NULL;
  struct Curl_header_store *pick = NULL;
  if(!name || !hout || !data ||
     (type > (CURLH_HEADER|CURLH_TRAILER|CURLH_CONNECT|CURLH_1XX|
              CURLH_PSEUDO)) || !type || (request < -1))
    return CURLHE_BAD_ARGUMENT;
  if(!Curl_llist_count(&data->state.httphdrs))
    return CURLHE_NOHEADERS; /* no headers available */
  if(request > data->state.requests)
    return CURLHE_NOREQUEST;
  if(request == -1)
    request = data->state.requests;

  /* we need a first round to count amount of this header */
  for(e = data->state.httphdrs.head; e; e = e->next) {
    hs = e->ptr;
    if(strcasecompare(hs->name, name) &&
       (hs->type & type) &&
       (hs->request == request)) {
      amount++;
      pick = hs;
      e_pick = e;
    }
  }
  if(!amount)
    return CURLHE_MISSING;
  else if(nameindex >= amount)
    return CURLHE_BADINDEX;

  if(nameindex == amount - 1)
    /* if the last or only occurrence is what's asked for, then we know it */
    hs = pick;
  else {
    for(e = data->state.httphdrs.head; e; e = e->next) {
      hs = e->ptr;
      if(strcasecompare(hs->name, name) &&
         (hs->type & type) &&
         (hs->request == request) &&
         (match++ == nameindex)) {
        e_pick = e;
        break;
      }
    }
    if(!e) /* this shouldn't happen */
      return CURLHE_MISSING;
  }
  /* this is the name we want */
  copy_header_external(hs, nameindex, amount, e_pick,
                       &data->state.headerout[0]);
  *hout = &data->state.headerout[0];
  return CURLHE_OK;
}

/* public API */
struct curl_header *curl_easy_nextheader(CURL *easy,
                                         unsigned int type,
                                         int request,
                                         struct curl_header *prev)
{
  struct Curl_easy *data = easy;
  struct Curl_llist_element *pick;
  struct Curl_llist_element *e;
  struct Curl_header_store *hs;
  size_t amount = 0;
  size_t index = 0;

  if(request > data->state.requests)
    return NULL;
  if(request == -1)
    request = data->state.requests;

  if(prev) {
    pick = prev->anchor;
    if(!pick)
      /* something is wrong */
      return NULL;
    pick = pick->next;
  }
  else
    pick = data->state.httphdrs.head;

  if(pick) {
    /* make sure it is the next header of the desired type */
    do {
      hs = pick->ptr;
      if((hs->type & type) && (hs->request == request))
        break;
      pick = pick->next;
    } while(pick);
  }

  if(!pick)
    /* no more headers available */
    return NULL;

  hs = pick->ptr;

  /* count number of occurrences of this name within the mask and figure out
     the index for the currently selected entry */
  for(e = data->state.httphdrs.head; e; e = e->next) {
    struct Curl_header_store *check = e->ptr;
    if(strcasecompare(hs->name, check->name) &&
       (check->request == request) &&
       (check->type & type))
      amount++;
    if(e == pick)
      index = amount - 1;
  }

  copy_header_external(hs, index, amount, pick,
                       &data->state.headerout[1]);
  return &data->state.headerout[1];
}

static CURLcode namevalue(char *header, size_t hlen, unsigned int type,
                           char **name, char **value)
{
  char *end = header + hlen - 1; /* point to the last byte */
  DEBUGASSERT(hlen);
  *name = header;

  if(type == CURLH_PSEUDO) {
    if(*header != ':')
      return CURLE_BAD_FUNCTION_ARGUMENT;
    header++;
  }

  /* Find the end of the header name */
  while(*header && (*header != ':'))
    ++header;

  if(*header)
    /* Skip over colon, null it */
    *header++ = 0;
  else
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* skip all leading space letters */
  while(*header && ISBLANK(*header))
    header++;

  *value = header;

  /* skip all trailing space letters */
  while((end > header) && ISSPACE(*end))
    *end-- = 0; /* nul terminate */
  return CURLE_OK;
}

static CURLcode unfold_value(struct Curl_easy *data, const char *value,
                             size_t vlen)  /* length of the incoming header */
{
  struct Curl_header_store *hs;
  struct Curl_header_store *newhs;
  size_t olen; /* length of the old value */
  size_t oalloc; /* length of the old name + value + separator */
  size_t offset;
  DEBUGASSERT(data->state.prevhead);
  hs = data->state.prevhead;
  olen = strlen(hs->value);
  offset = hs->value - hs->buffer;
  oalloc = olen + offset + 1;

  /* skip all trailing space letters */
  while(vlen && ISSPACE(value[vlen - 1]))
    vlen--;

  /* save only one leading space */
  while((vlen > 1) && ISBLANK(value[0]) && ISBLANK(value[1])) {
    vlen--;
    value++;
  }

  /* since this header block might move in the realloc below, it needs to
     first be unlinked from the list and then re-added again after the
     realloc */
  Curl_llist_remove(&data->state.httphdrs, &hs->node, NULL);

  /* new size = struct + new value length + old name+value length */
  newhs = Curl_saferealloc(hs, sizeof(*hs) + vlen + oalloc + 1);
  if(!newhs)
    return CURLE_OUT_OF_MEMORY;
  /* ->name' and ->value point into ->buffer (to keep the header allocation
     in a single memory block), which now potentially have moved. Adjust
     them. */
  newhs->name = newhs->buffer;
  newhs->value = &newhs->buffer[offset];

  /* put the data at the end of the previous data, not the newline */
  memcpy(&newhs->value[olen], value, vlen);
  newhs->value[olen + vlen] = 0; /* null-terminate at newline */

  /* insert this node into the list of headers */
  Curl_llist_insert_next(&data->state.httphdrs, data->state.httphdrs.tail,
                         newhs, &newhs->node);
  data->state.prevhead = newhs;
  return CURLE_OK;
}


/*
 * Curl_headers_push() gets passed a full HTTP header to store. It gets called
 * immediately before the header callback. The header is CRLF terminated.
 */
CURLcode Curl_headers_push(struct Curl_easy *data, const char *header,
                           unsigned char type)
{
  char *value = NULL;
  char *name = NULL;
  char *end;
  size_t hlen; /* length of the incoming header */
  struct Curl_header_store *hs;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  if((header[0] == '\r') || (header[0] == '\n'))
    /* ignore the body separator */
    return CURLE_OK;

  end = strchr(header, '\r');
  if(!end) {
    end = strchr(header, '\n');
    if(!end)
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  hlen = end - header + 1;

  if((header[0] == ' ') || (header[0] == '\t')) {
    if(data->state.prevhead)
      /* line folding, append value to the previous header's value */
      return unfold_value(data, header, hlen);
    else {
      /* Can't unfold without a previous header. Instead of erroring, just
         pass the leading blanks. */
      while(hlen && ISBLANK(*header)) {
        header++;
        hlen--;
      }
      if(!hlen)
        return CURLE_WEIRD_SERVER_REPLY;
    }
  }

  hs = calloc(1, sizeof(*hs) + hlen);
  if(!hs)
    return CURLE_OUT_OF_MEMORY;
  memcpy(hs->buffer, header, hlen);
  hs->buffer[hlen] = 0; /* nul terminate */

  result = namevalue(hs->buffer, hlen, type, &name, &value);
  if(result)
    goto fail;

  hs->name = name;
  hs->value = value;
  hs->type = type;
  hs->request = data->state.requests;

  /* insert this node into the list of headers */
  Curl_llist_insert_next(&data->state.httphdrs, data->state.httphdrs.tail,
                         hs, &hs->node);
  data->state.prevhead = hs;
  return CURLE_OK;
fail:
  free(hs);
  return result;
}

/*
 * Curl_headers_init(). Init the headers subsystem.
 */
static void headers_init(struct Curl_easy *data)
{
  Curl_llist_init(&data->state.httphdrs, NULL);
  data->state.prevhead = NULL;
}

/*
 * Curl_headers_cleanup(). Free all stored headers and associated memory.
 */
CURLcode Curl_headers_cleanup(struct Curl_easy *data)
{
  struct Curl_llist_element *e;
  struct Curl_llist_element *n;

  for(e = data->state.httphdrs.head; e; e = n) {
    struct Curl_header_store *hs = e->ptr;
    n = e->next;
    free(hs);
  }
  headers_init(data);
  return CURLE_OK;
}

#else /* HTTP-disabled builds below */

CURLHcode curl_easy_header(CURL *easy,
                           const char *name,
                           size_t index,
                           unsigned int origin,
                           int request,
                           struct curl_header **hout)
{
  (void)easy;
  (void)name;
  (void)index;
  (void)origin;
  (void)request;
  (void)hout;
  return CURLHE_NOT_BUILT_IN;
}

struct curl_header *curl_easy_nextheader(CURL *easy,
                                         unsigned int type,
                                         int request,
                                         struct curl_header *prev)
{
  (void)easy;
  (void)type;
  (void)request;
  (void)prev;
  return NULL;
}
#endif
