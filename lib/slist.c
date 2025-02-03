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

#include "slist.h"

/* The last #include files should be: */
#include "fetch_memory.h"
#include "memdebug.h"

/* returns last node in linked list */
static struct fetch_slist *slist_get_last(struct fetch_slist *list)
{
  struct fetch_slist     *item;

  /* if caller passed us a NULL, return now */
  if(!list)
    return NULL;

  /* loop through to find the last item */
  item = list;
  while(item->next) {
    item = item->next;
  }
  return item;
}

/*
 * Curl_slist_append_nodup() appends a string to the linked list. Rather than
 * copying the string in dynamic storage, it takes its ownership. The string
 * should have been malloc()ated. Curl_slist_append_nodup always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function.
 * If an error occurs, NULL is returned and the string argument is NOT
 * released.
 */
struct fetch_slist *Curl_slist_append_nodup(struct fetch_slist *list, char *data)
{
  struct fetch_slist     *last;
  struct fetch_slist     *new_item;

  DEBUGASSERT(data);

  new_item = malloc(sizeof(struct fetch_slist));
  if(!new_item)
    return NULL;

  new_item->next = NULL;
  new_item->data = data;

  /* if this is the first item, then new_item *is* the list */
  if(!list)
    return new_item;

  last = slist_get_last(list);
  last->next = new_item;
  return list;
}

/*
 * fetch_slist_append() appends a string to the linked list. It always returns
 * the address of the first record, so that you can use this function as an
 * initialization function as well as an append function. If you find this
 * bothersome, then simply create a separate _init function and call it
 * appropriately from within the program.
 */
struct fetch_slist *fetch_slist_append(struct fetch_slist *list,
                                     const char *data)
{
  char *dupdata = strdup(data);

  if(!dupdata)
    return NULL;

  list = Curl_slist_append_nodup(list, dupdata);
  if(!list)
    free(dupdata);

  return list;
}

/*
 * Curl_slist_duplicate() duplicates a linked list. It always returns the
 * address of the first record of the cloned list or NULL in case of an
 * error (or if the input list was NULL).
 */
struct fetch_slist *Curl_slist_duplicate(struct fetch_slist *inlist)
{
  struct fetch_slist *outlist = NULL;
  struct fetch_slist *tmp;

  while(inlist) {
    tmp = fetch_slist_append(outlist, inlist->data);

    if(!tmp) {
      fetch_slist_free_all(outlist);
      return NULL;
    }

    outlist = tmp;
    inlist = inlist->next;
  }
  return outlist;
}

/* be nice and clean up resources */
void fetch_slist_free_all(struct fetch_slist *list)
{
  struct fetch_slist     *next;
  struct fetch_slist     *item;

  if(!list)
    return;

  item = list;
  do {
    next = item->next;
    Curl_safefree(item->data);
    free(item);
    item = next;
  } while(next);
}
