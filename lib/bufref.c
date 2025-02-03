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
#include "urldata.h"
#include "bufref.h"
#include "strdup.h"

#include "fetch_memory.h"
#include "memdebug.h"

#define SIGNATURE 0x5c48e9b2 /* Random pattern. */

/*
 * Init a bufref struct.
 */
void Fetch_bufref_init(struct bufref *br)
{
  DEBUGASSERT(br);
  br->dtor = NULL;
  br->ptr = NULL;
  br->len = 0;

#ifdef DEBUGBUILD
  br->signature = SIGNATURE;
#endif
}

/*
 * Free the buffer and re-init the necessary fields. It does not touch the
 * 'signature' field and thus this buffer reference can be reused.
 */

void Fetch_bufref_free(struct bufref *br)
{
  DEBUGASSERT(br);
  DEBUGASSERT(br->signature == SIGNATURE);
  DEBUGASSERT(br->ptr || !br->len);

  if (br->ptr && br->dtor)
    br->dtor((void *)br->ptr);

  br->dtor = NULL;
  br->ptr = NULL;
  br->len = 0;
}

/*
 * Set the buffer reference to new values. The previously referenced buffer
 * is released before assignment.
 */
void Fetch_bufref_set(struct bufref *br, const void *ptr, size_t len,
                     void (*dtor)(void *))
{
  DEBUGASSERT(ptr || !len);
  DEBUGASSERT(len <= FETCH_MAX_INPUT_LENGTH);

  Fetch_bufref_free(br);
  br->ptr = (const unsigned char *)ptr;
  br->len = len;
  br->dtor = dtor;
}

/*
 * Get a pointer to the referenced buffer.
 */
const unsigned char *Fetch_bufref_ptr(const struct bufref *br)
{
  DEBUGASSERT(br);
  DEBUGASSERT(br->signature == SIGNATURE);
  DEBUGASSERT(br->ptr || !br->len);

  return br->ptr;
}

/*
 * Get the length of the referenced buffer data.
 */
size_t Fetch_bufref_len(const struct bufref *br)
{
  DEBUGASSERT(br);
  DEBUGASSERT(br->signature == SIGNATURE);
  DEBUGASSERT(br->ptr || !br->len);

  return br->len;
}

FETCHcode Fetch_bufref_memdup(struct bufref *br, const void *ptr, size_t len)
{
  unsigned char *cpy = NULL;

  DEBUGASSERT(br);
  DEBUGASSERT(br->signature == SIGNATURE);
  DEBUGASSERT(br->ptr || !br->len);
  DEBUGASSERT(ptr || !len);
  DEBUGASSERT(len <= FETCH_MAX_INPUT_LENGTH);

  if (ptr)
  {
    cpy = Fetch_memdup0(ptr, len);
    if (!cpy)
      return FETCHE_OUT_OF_MEMORY;
  }

  Fetch_bufref_set(br, cpy, len, fetch_free);
  return FETCHE_OK;
}
