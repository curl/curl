/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2002, Daniel Stenberg, <daniel@haxx.se>, et al
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdlib.h>

#include "llist.h"

#ifdef MALLOCDEBUG
/* this must be the last include file */
#include "memdebug.h"
#endif
void 
curl_llist_init(curl_llist *l, curl_llist_dtor dtor)
{
  l->size = 0;
  l->dtor = dtor;
  l->head = NULL;
  l->tail = NULL;
}

curl_llist *
curl_llist_alloc(curl_llist_dtor dtor)
{
  curl_llist *list;

  list = (curl_llist *)malloc(sizeof(curl_llist));
  if(NULL == list)
    return NULL;

  curl_llist_init(list, dtor);

  return list;
}

int
curl_llist_insert_next(curl_llist *list, curl_llist_element *e, const void *p)
{
  curl_llist_element  *ne;

  ne = (curl_llist_element *) malloc(sizeof(curl_llist_element));
  ne->ptr = (void *) p;
  if (list->size == 0) {
    list->head = ne;
    list->head->prev = NULL;
    list->head->next = NULL;
    list->tail = ne;
  } else {
    ne->next = e->next;
    ne->prev = e;
    if (e->next) {
      e->next->prev = ne;
    } else {
      list->tail = ne;
    }
    e->next = ne;
  }

  ++list->size;

  return 1;
}

int 
curl_llist_insert_prev(curl_llist *list, curl_llist_element *e, const void *p)
{
  curl_llist_element *ne;

  ne = (curl_llist_element *) malloc(sizeof(curl_llist_element));
  ne->ptr = (void *) p;
  if (list->size == 0) {
    list->head = ne;
    list->head->prev = NULL;
    list->head->next = NULL;
    list->tail = ne;
  } else {
    ne->next = e;
    ne->prev = e->prev;
    if (e->prev)
      e->prev->next = ne;
    else
      list->head = ne;
    e->prev = ne;
  }

  ++list->size;

  return 1;
}

int 
curl_llist_remove(curl_llist *list, curl_llist_element *e, void *user)
{
  if (e == NULL || list->size == 0)
    return 1;

  if (e == list->head) {
    list->head = e->next;

    if (list->head == NULL)
      list->tail = NULL;
    else
      e->next->prev = NULL;
  } else {
    e->prev->next = e->next;
    if (!e->next)
      list->tail = e->prev;
    else
      e->next->prev = e->prev;
  }

  list->dtor(user, e->ptr);
  free(e);
  --list->size;

  return 1;
}

int 
curl_llist_remove_next(curl_llist *list, curl_llist_element *e, void *user)
{
  return curl_llist_remove(list, e->next, user);
}

int 
curl_llist_remove_prev(curl_llist *list, curl_llist_element *e, void *user)
{
  return curl_llist_remove(list, e->prev, user);
}

size_t 
curl_llist_count(curl_llist *list)
{
  return list->size;
}

void 
curl_llist_destroy(curl_llist *list, void *user)
{
  while (list->size > 0) {
    curl_llist_remove(list, CURL_LLIST_TAIL(list), user);
  }

  free(list);
  list = NULL;
}
