#ifndef __LLIST_H
#define __LLIST_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"
#include <stddef.h>

typedef void (*curl_llist_dtor)(void *, void *);

typedef struct _curl_llist_element {
  void *ptr;

  struct _curl_llist_element *prev;
  struct _curl_llist_element *next;
} curl_llist_element;

typedef struct _curl_llist {
  curl_llist_element *head;
  curl_llist_element *tail;

  curl_llist_dtor dtor;

  size_t size;
} curl_llist;

void Curl_llist_init(curl_llist *, curl_llist_dtor);
curl_llist *Curl_llist_alloc(curl_llist_dtor);
int Curl_llist_insert_next(curl_llist *, curl_llist_element *, const void *);
int Curl_llist_insert_prev(curl_llist *, curl_llist_element *, const void *);
int Curl_llist_remove(curl_llist *, curl_llist_element *, void *);
int Curl_llist_remove_next(curl_llist *, curl_llist_element *, void *);
size_t Curl_llist_count(curl_llist *);
void Curl_llist_destroy(curl_llist *, void *);

#define CURL_LLIST_HEAD(__l) ((__l)->head)
#define CURL_LLIST_TAIL(__l) ((__l)->tail)
#define CURL_LLIST_NEXT(__e) ((__e)->next)
#define CURL_LLIST_PREV(__e) ((__e)->prev)
#define CURL_LLIST_VALP(__e) ((__e)->ptr)
#define CURL_LLIST_IS_TAIL(__e) ((__e)->next ? 0 : 1)
#define CURL_LLIST_IS_HEAD(__e) ((__e)->prev ? 0 : 1)

#endif
