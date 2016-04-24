/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#include "strdup.h"
#include "fileinfo.h"
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

  Curl_safefree(finfo->b_data);

  free(finfo);
}
