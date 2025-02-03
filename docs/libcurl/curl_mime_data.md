---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_data
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_data_cb (3)
  - fetch_mime_name (3)
  - fetch_mime_type (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_data - set a mime part's body data from memory

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_data(fetch_mimepart *part, const char *data,
                        size_t datasize);
~~~

# DESCRIPTION

fetch_mime_data(3) sets a mime part's body content from memory data.

*part* is the mime part to assign contents to, created with
fetch_mime_addpart(3).

*data* points to the data that gets copied by this function. The storage
may safely be reused after the call.

*datasize* is the number of bytes *data* points to. It can be set to
*FETCH_ZERO_TERMINATED* to indicate *data* is a null-terminated
character string.

Setting a part's contents multiple times is valid: only the value set by the
last call is retained. It is possible to unassign part's contents by setting
*data* to NULL.

Setting large data is memory consuming: one might consider using
fetch_mime_data_cb(3) in such a case.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  fetch_mime *mime;
  fetch_mimepart *part;

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* create a mime handle */
    mime = fetch_mime_init(fetch);

    /* add a part */
    part = fetch_mime_addpart(mime);

    /* add data to the part  */
    fetch_mime_data(part, "raw contents to send", FETCH_ZERO_TERMINATED);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
