/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <stdlib.h>

#include "llist.h"
#include "curl_memory.h"

/* this must be the last include file */
#include "memdebug.h"

static void
llist_init(struct curl_llist *l, curl_llist_dtor dtor)
{
  l->size = 0;
  l->dtor = dtor;
  l->head = NULL;
  l->tail = NULL;
}

struct curl_llist *
Curl_llist_alloc(curl_llist_dtor dtor)
{
  struct curl_llist *list;

  list = malloc(sizeof(struct curl_llist));
  if(NULL == list)
    return NULL;

  llist_init(list, dtor);

  return list;
}

/*
 * Curl_llist_insert_next()
 *
 * Inserts a new list element after the given one 'e'. If the given existing
 * entry is NULL and the list already has elements, the new one will be
 * inserted first in the list.
 *
 * Returns: 1 on success and 0 on failure.
 */
int
Curl_llist_insert_next(struct curl_llist *list, struct curl_llist_element *e,
                       const void *p)
{
  struct curl_llist_element *ne = malloc(sizeof(struct curl_llist_element));
  if(!ne)
    return 0;

  ne->ptr = (void *) p;
  if(list->size == 0) {
    list->head = ne;
    list->head->prev = NULL;
    list->head->next = NULL;
    list->tail = ne;
  }
  else {
    /* if 'e' is NULL here, we insert the new element first in the list */
    ne->next = e?e->next:list->head;
    ne->prev = e;
    if(!e) {
      list->head->prev = ne;
      list->head = ne;
    }
    else if(e->next) {
      e->next->prev = ne;
    }
    else {
      list->tail = ne;
    }
    if(e)
      e->next = ne;
  }

  ++list->size;

  return 1;
}

int
Curl_llist_remove(struct curl_llist *list, struct curl_llist_element *e,
                  void *user)
{
  if(e == NULL || list->size == 0)
    return 1;

  if(e == list->head) {
    list->head = e->next;

    if(list->head == NULL)
      list->tail = NULL;
    else
      e->next->prev = NULL;
  } else {
    e->prev->next = e->next;
    if(!e->next)
      list->tail = e->prev;
    else
      e->next->prev = e->prev;
  }

  list->dtor(user, e->ptr);

  free(e);
  --list->size;

  return 1;
}

void
Curl_llist_destroy(struct curl_llist *list, void *user)
{
  if(list) {
    while(list->size > 0)
      Curl_llist_remove(list, list->tail, user);

    free(list);
  }
}

size_t
Curl_llist_count(struct curl_llist *list)
{
  return list->size;
}

int Curl_llist_move(struct curl_llist *list, struct curl_llist_element *e,
                    struct curl_llist *to_list, struct curl_llist_element *to_e)
{
  /* Remove element from list */
  if(e == NULL || list->size == 0)
    return 0;

  if(e == list->head) {
    list->head = e->next;

    if(list->head == NULL)
      list->tail = NULL;
    else
      e->next->prev = NULL;
  }
  else {
    e->prev->next = e->next;
    if(!e->next)
      list->tail = e->prev;
    else
      e->next->prev = e->prev;
  }

  --list->size;

  /* Add element to to_list after to_e */
  if(to_list->size == 0) {
    to_list->head = e;
    to_list->head->prev = NULL;
    to_list->head->next = NULL;
    to_list->tail = e;
  }
  else {
    e->next = to_e->next;
    e->prev = to_e;
    if(to_e->next) {
      to_e->next->prev = e;
    }
    else {
      to_list->tail = e;
    }
    to_e->next = e;
  }

  ++to_list->size;

  return 1;
}
