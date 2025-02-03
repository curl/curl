---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RESUME_FROM
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_INFILESIZE (3)
  - FETCHOPT_RANGE (3)
  - FETCHOPT_RESUME_FROM_LARGE (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_RESUME_FROM - offset to resume transfer from

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RESUME_FROM, long from);
~~~

# DESCRIPTION

Pass a long as parameter. It contains the offset in number of bytes that you
want the transfer to start from. Set this option to 0 to make the transfer
start from the beginning (effectively disabling resume). For FTP, set this
option to -1 to make the transfer start from the end of the target file
(useful to continue an interrupted upload).

When doing uploads with FTP, the resume position is where in the local/source
file libfetch should try to resume the upload from and it then appends the
source file to the remote target file.

If you need to resume a transfer beyond the 2GB limit, use
FETCHOPT_RESUME_FROM_LARGE(3) instead.

# DEFAULT

0, not used

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    long size_of_file;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com");

    /* resume upload at byte index 200 */
    fetch_easy_setopt(fetch, FETCHOPT_RESUME_FROM, 200L);

    /* ask for upload */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* set total data amount to expect */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE, size_of_file);

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
