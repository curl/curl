---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CHUNK_DATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CHUNK_BGN_FUNCTION (3)
  - FETCHOPT_WILDCARDMATCH (3)
Protocol:
  - FTP
Added-in: 7.21.0
---

# NAME

FETCHOPT_CHUNK_DATA - pointer passed to the FTP chunk callbacks

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CHUNK_DATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libfetch and passed as the ptr
argument to the FETCHOPT_CHUNK_BGN_FUNCTION(3) and
FETCHOPT_CHUNK_END_FUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <stdio.h>

struct callback_data {
   FILE *output;
};

static long file_is_coming(struct fetch_fileinfo *finfo,
                           void *ptr,
                           int remains)
{
  struct callback_data *data = ptr;
  printf("%3d %40s %10luB ", remains, finfo->filename,
         (unsigned long)finfo->size);

  switch(finfo->filetype) {
  case FETCHFILETYPE_DIRECTORY:
    printf(" DIR\n");
    break;
  case FETCHFILETYPE_FILE:
    printf("FILE ");
    break;
  default:
    printf("OTHER\n");
    break;
  }

  if(finfo->filetype == FETCHFILETYPE_FILE) {
    /* do not transfer files >= 50B */
    if(finfo->size > 50) {
      printf("SKIPPED\n");
      return FETCH_CHUNK_BGN_FUNC_SKIP;
    }

    data->output = fopen(finfo->filename, "wb");
    if(!data->output) {
      return FETCH_CHUNK_BGN_FUNC_FAIL;
    }
  }

  return FETCH_CHUNK_BGN_FUNC_OK;
}

int main()
{
  /* data for callback */
  struct callback_data callback_info;

  FETCH *fetch = fetch_easy_init();

  /* callback is called before download of concrete file started */
  fetch_easy_setopt(fetch, FETCHOPT_CHUNK_BGN_FUNCTION, file_is_coming);
  fetch_easy_setopt(fetch, FETCHOPT_CHUNK_DATA, &callback_info);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
