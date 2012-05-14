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

#include "rawstr.h"

#include "tool_metalink.h"
#include "tool_getparam.h"
#include "tool_paramhlp.h"

#include "memdebug.h" /* keep this as LAST include */

/* Copied from tool_getparam.c */
#define GetStr(str,val) do { \
  if(*(str)) { \
    free(*(str)); \
    *(str) = NULL; \
  } \
  if((val)) \
    *(str) = strdup((val)); \
  if(!(val)) \
    return PARAM_NO_MEM; \
} WHILE_FALSE

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

int parse_metalink(struct Configurable *config, const char *infile)
{
  metalink_error_t r;
  metalink_t* metalink;
  metalink_file_t **files;
  struct metalink *ml;

  r = metalink_parse_file(infile, &metalink);

  if(r != 0) {
    return -1;
  }
  if(metalink->files == NULL) {
    fprintf(config->errors, "\nMetalink does not contain any file.\n");
    return 0;
  }
  ml = new_metalink(metalink);

  if(config->metalink_list) {
    config->metalink_last->next = ml;
    config->metalink_last = ml;
  }
  else {
    config->metalink_list = config->metalink_last = ml;
  }

  for(files = metalink->files; *files; ++files) {
    struct getout *url;
    /* Skip an entry which has no resource. */
    if(!(*files)->resources) {
      fprintf(config->errors, "\nFile %s does not have any resource.\n",
              (*files)->name);
      continue;
    }
    if(config->url_get ||
       ((config->url_get = config->url_list) != NULL)) {
      /* there's a node here, if it already is filled-in continue to
         find an "empty" node */
      while(config->url_get && (config->url_get->flags & GETOUT_URL))
        config->url_get = config->url_get->next;
    }

    /* now there might or might not be an available node to fill in! */

    if(config->url_get)
      /* existing node */
      url = config->url_get;
    else
      /* there was no free node, create one! */
      url=new_getout(config);

    if(url) {
      struct metalinkfile *mlfile;
      /* Set name as url */
      GetStr(&url->url, (*files)->name);

      /* set flag metalink here */
      url->flags |= GETOUT_URL | GETOUT_METALINK;
      mlfile = new_metalinkfile(*files);

      if(config->metalinkfile_list) {
        config->metalinkfile_last->next = mlfile;
        config->metalinkfile_last = mlfile;
      }
      else {
        config->metalinkfile_list = config->metalinkfile_last = mlfile;
      }
    }
  }
  return 0;
}

/*
 * Returns nonzero if content_type includes mediatype.
 */
static int check_content_type(const char *content_type, const char *media_type)
{
  const char *ptr = content_type;
  size_t media_type_len = strlen(media_type);
  for(; *ptr && (*ptr == ' ' || *ptr == '\t'); ++ptr);
  if(!*ptr) {
    return 0;
  }
  return Curl_raw_nequal(ptr, media_type, media_type_len) &&
    (*(ptr+media_type_len) == '\0' || *(ptr+media_type_len) == ' ' ||
     *(ptr+media_type_len) == '\t' || *(ptr+media_type_len) == ';');
}

int check_metalink_content_type(const char *content_type)
{
  return check_content_type(content_type, "application/metalink+xml");
}
