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
#include "test.h"

#include "testutil.h"
#include "memdebug.h"

struct chunk_data
{
  int remains;
  int print_content;
};

static long chunk_bgn(const void *f, void *ptr, int remains)
{
  const struct fetch_fileinfo *finfo = f;
  struct chunk_data *ch_d = ptr;
  ch_d->remains = remains;

  printf("=============================================================\n");
  printf("Remains:      %d\n", remains);
  printf("Filename:     %s\n", finfo->filename);
  if (finfo->strings.perm)
  {
    printf("Permissions:  %s", finfo->strings.perm);
    if (finfo->flags & FETCHFINFOFLAG_KNOWN_PERM)
      printf(" (parsed => %o)", finfo->perm);
    printf("\n");
  }
  printf("Size:         %ldB\n", (long)finfo->size);
  if (finfo->strings.user)
    printf("User:         %s\n", finfo->strings.user);
  if (finfo->strings.group)
    printf("Group:        %s\n", finfo->strings.group);
  if (finfo->strings.time)
    printf("Time:         %s\n", finfo->strings.time);
  printf("Filetype:     ");
  switch (finfo->filetype)
  {
  case FETCHFILETYPE_FILE:
    printf("regular file\n");
    break;
  case FETCHFILETYPE_DIRECTORY:
    printf("directory\n");
    break;
  case FETCHFILETYPE_SYMLINK:
    printf("symlink\n");
    printf("Target:       %s\n", finfo->strings.target);
    break;
  default:
    printf("other type\n");
    break;
  }
  if (finfo->filetype == FETCHFILETYPE_FILE)
  {
    ch_d->print_content = 1;
    printf("Content:\n"
           "-------------------------------------------------------------\n");
  }
  if (strcmp(finfo->filename, "someothertext.txt") == 0)
  {
    printf("# THIS CONTENT WAS SKIPPED IN CHUNK_BGN CALLBACK #\n");
    return FETCH_CHUNK_BGN_FUNC_SKIP;
  }
  return FETCH_CHUNK_BGN_FUNC_OK;
}

static long chunk_end(void *ptr)
{
  struct chunk_data *ch_d = ptr;
  if (ch_d->print_content)
  {
    ch_d->print_content = 0;
    printf("-------------------------------------------------------------\n");
  }
  if (ch_d->remains == 1)
    printf("=============================================================\n");
  return FETCH_CHUNK_END_FUNC_OK;
}

FETCHcode test(char *URL)
{
  FETCH *handle = NULL;
  FETCHcode res = FETCHE_OK;
  struct chunk_data chunk_data = {0, 0};
  fetch_global_init(FETCH_GLOBAL_ALL);
  handle = fetch_easy_init();
  if (!handle)
  {
    res = FETCHE_OUT_OF_MEMORY;
    goto test_cleanup;
  }

  test_setopt(handle, FETCHOPT_URL, URL);
  test_setopt(handle, FETCHOPT_WILDCARDMATCH, 1L);
  test_setopt(handle, FETCHOPT_CHUNK_BGN_FUNCTION, chunk_bgn);
  test_setopt(handle, FETCHOPT_CHUNK_END_FUNCTION, chunk_end);
  test_setopt(handle, FETCHOPT_CHUNK_DATA, &chunk_data);

  res = fetch_easy_perform(handle);

test_cleanup:
  if (handle)
    fetch_easy_cleanup(handle);
  fetch_global_cleanup();
  return res;
}
