---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_addpart
Section: 3
Source: libfetch
See-also:
  - fetch_mime_data (3)
  - fetch_mime_data_cb (3)
  - fetch_mime_encoder (3)
  - fetch_mime_filedata (3)
  - fetch_mime_filename (3)
  - fetch_mime_headers (3)
  - fetch_mime_init (3)
  - fetch_mime_name (3)
  - fetch_mime_subparts (3)
  - fetch_mime_type (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_addpart - append a new empty part to a mime structure

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

fetch_mimepart *fetch_mime_addpart(fetch_mime *mime);
~~~

# DESCRIPTION

fetch_mime_addpart(3) creates and appends a new empty part to the given
mime structure and returns a handle to it. The returned part handle can
subsequently be populated using functions from the mime API.

*mime* is the handle of the mime structure in which the new part must be
appended.

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

    /* continue and set name + data to the part */
    fetch_mime_data(part, "This is the field data", FETCH_ZERO_TERMINATED);
    fetch_mime_name(part, "data");
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A mime part structure handle, or NULL upon failure.
