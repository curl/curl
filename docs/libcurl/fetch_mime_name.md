---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_name
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_data (3)
  - fetch_mime_type (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_name - set a mime part's name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_name(fetch_mimepart *part, const char *name);
~~~

# DESCRIPTION

fetch_mime_name(3) sets a mime part's name. This is the way HTTP form
fields are named.

*part* is the part's handle to assign a name to.

*name* points to the null-terminated name string.

The name string is copied into the part, thus the associated storage may
safely be released or reused after call. Setting a part's name multiple times
is valid: only the value set by the last call is retained. It is possible to
reset the name of a part by setting *name* to NULL.

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

    /* give the part a name */
    fetch_mime_name(part, "shoe_size");
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
