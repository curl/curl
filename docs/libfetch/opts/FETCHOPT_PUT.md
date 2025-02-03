---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PUT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPGET (3)
  - FETCHOPT_MIMEPOST (3)
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_PUT - make an HTTP PUT request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PUT, long put);
~~~

# DESCRIPTION

A parameter set to 1 tells the library to use HTTP PUT to transfer data. The
data should be set with FETCHOPT_READDATA(3) and
FETCHOPT_INFILESIZE(3).

This option is **deprecated** since version 7.12.1. Use FETCHOPT_UPLOAD(3).

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *src = userdata;
  /* copy as much data as possible into the 'ptr' buffer, but no more than
     'size' * 'nmemb' bytes */
  size_t retcode = fread(ptr, size, nmemb, src);

  return retcode;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FILE *src = fopen("local-file", "r");
    fetch_off_t fsize; /* set this to the size of the input file */

    /* we want to use our own read function */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_cb);

    /* enable PUT */
    fetch_easy_setopt(fetch, FETCHOPT_PUT, 1L);

    /* specify target */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/dir/to/newfile");

    /* now specify which pointer to pass to our callback */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, src);

    /* Set the size of the file to upload */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE, (fetch_off_t)fsize);

    /* Now run off and do what you have been told */
    fetch_easy_perform(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.12.1.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
