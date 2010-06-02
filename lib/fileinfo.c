/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <stdlib.h>
#include "strdup.h"
#include "fileinfo.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

struct curl_fileinfo *Curl_fileinfo_alloc(void)
{
  struct curl_fileinfo *tmp = malloc(sizeof(struct curl_fileinfo));
  if(!tmp)
    return NULL;
  memset(tmp, 0, sizeof(struct curl_fileinfo));
  return tmp;
}

void Curl_fileinfo_dtor(void *user, void *element)
{
  struct curl_fileinfo *finfo = element;
  (void) user;
  if(!finfo)
    return;

  if(finfo->b_data){
    free(finfo->b_data);
  }

  free(finfo);
}

struct curl_fileinfo *Curl_fileinfo_dup(const struct curl_fileinfo *src)
{
  struct curl_fileinfo *ptr = malloc(sizeof(struct curl_fileinfo));
  if(!ptr)
    return NULL;
  *ptr = *src;

  ptr->b_data = malloc(src->b_size);
  if(!ptr->b_data) {
    free(ptr);
    return NULL;
  }
  else {
    memcpy(ptr->b_data, src->b_data, src->b_size);
    return ptr;
  }
}
