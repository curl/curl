/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"

#include "tool_mfiles.h"

#include "memdebug.h" /* keep this as LAST include */

static void AppendNode(struct multi_files **first,
                       struct multi_files **last,
                       struct multi_files  *new)
{
  DEBUGASSERT(((*first) && (*last)) || ((!*first) && (!*last)));

  if(*last)
    (*last)->next = new;
  else
    *first = new;
  *last = new;
}

/*
 * AddMultiFiles: Add a new list node possibly followed with a type_name.
 *
 * multi_first argument is the address of a pointer to the first element
 * of the multi_files linked list. A NULL pointer indicates empty list.
 *
 * multi_last argument is the address of a pointer to the last element
 * of the multi_files linked list. A NULL pointer indicates empty list.
 *
 * Pointers stored in multi_first and multi_last are modified while
 * function is executed. An out of memory condition free's the whole
 * list and returns with pointers stored in multi_first and multi_last
 * set to NULL and a NULL function result.
 *
 * Function returns same pointer as stored at multi_last.
 */

struct multi_files *AddMultiFiles(const char *file_name,
                                  const char *type_name,
                                  const char *show_filename,
                                  struct multi_files **multi_first,
                                  struct multi_files **multi_last)
{
  struct multi_files *multi;
  struct multi_files *multi_type;
  struct multi_files *multi_name;

  multi = calloc(1, sizeof(struct multi_files));
  if(multi) {
    multi->form.option = CURLFORM_FILE;
    multi->form.value = file_name;
    AppendNode(multi_first, multi_last, multi);
  }
  else {
    FreeMultiInfo(multi_first, multi_last);
    return NULL;
  }

  if(type_name) {
    multi_type = calloc(1, sizeof(struct multi_files));
    if(multi_type) {
      multi_type->form.option = CURLFORM_CONTENTTYPE;
      multi_type->form.value = type_name;
      AppendNode(multi_first, multi_last, multi_type);
    }
    else {
      FreeMultiInfo(multi_first, multi_last);
      return NULL;
    }
  }

  if(show_filename) {
    multi_name = calloc(1, sizeof(struct multi_files));
    if(multi_name) {
      multi_name->form.option = CURLFORM_FILENAME;
      multi_name->form.value = show_filename;
      AppendNode(multi_first, multi_last, multi_name);
    }
    else {
      FreeMultiInfo(multi_first, multi_last);
      return NULL;
    }
  }

  return *multi_last;
}

/*
 * FreeMultiInfo: Free the items of the list.
 */

void FreeMultiInfo(struct multi_files **multi_first,
                   struct multi_files **multi_last)
{
  struct multi_files *next;
  struct multi_files *item = *multi_first;

  while(item) {
    next = item->next;
    Curl_safefree(item);
    item = next;
  }
  *multi_first = NULL;
  if(multi_last)
    *multi_last = NULL;
}

