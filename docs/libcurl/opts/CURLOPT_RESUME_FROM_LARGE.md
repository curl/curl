---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RESUME_FROM_LARGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_INFILESIZE_LARGE (3)
  - FETCHOPT_RANGE (3)
  - FETCHOPT_RESUME_FROM (3)
Protocol:
  - All
Added-in: 7.11.0
---

# NAME

FETCHOPT_RESUME_FROM_LARGE - offset to resume transfer from

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RESUME_FROM_LARGE,
                          fetch_off_t from);
~~~

# DESCRIPTION

Pass a fetch_off_t as parameter. It contains the offset in number of bytes that
you want the transfer to start from. Set this option to 0 to make the transfer
start from the beginning (effectively disabling resume). For FTP, set this
option to -1 to make the transfer start from the end of the target file
(useful to continue an interrupted upload).

When doing uploads with FTP, the resume position is where in the local/source
file libfetch should try to resume the upload from and it appends the source
file to the remote target file.

# DEFAULT

0, not used

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_off_t resume_position; /* get it somehow */
    fetch_off_t file_size; /* get it somehow as well */

    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com");

    /* resuming upload at this position, possibly beyond 2GB */
    fetch_easy_setopt(fetch, FETCHOPT_RESUME_FROM_LARGE, resume_position);

    /* ask for upload */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* set total data amount to expect */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE, file_size);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
