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
#include "tool_setup.h"
#include "tool_metalink.h"

#include "memdebug.h" /* keep this as LAST include */

struct metalinkfile *new_metalinkfile(metalink_file_t *metalinkfile) {
  struct metalinkfile *f;
  f = (struct metalinkfile*)malloc(sizeof(struct metalinkfile));
  f->file = metalinkfile;
  f->next = NULL;
  return f;
}

struct metalink *new_metalink(metalink_t *metalink) {
  struct metalink *ml;
  ml = (struct metalink*)malloc(sizeof(struct metalink));
  ml->metalink = metalink;
  ml->next = NULL;
  return ml;
}

int count_next_metalink_resource(struct metalinkfile *mlfile)
{
  int count = 0;
  metalink_resource_t **mlres;
  for(mlres = mlfile->file->resources; *mlres; ++mlres, ++count);
  return count;
}

void clean_metalink(struct Configurable *config)
{
  while(config->metalinkfile_list) {
    struct metalinkfile *mlfile = config->metalinkfile_list;
    config->metalinkfile_list = config->metalinkfile_list->next;
    Curl_safefree(mlfile);
  }
  config->metalinkfile_last = 0;
  while(config->metalink_list) {
    struct metalink *ml = config->metalink_list;
    config->metalink_list = config->metalink_list->next;
    metalink_delete(ml->metalink);
    Curl_safefree(ml);
  }
  config->metalink_last = 0;
}
