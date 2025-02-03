---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_type
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_data (3)
  - fetch_mime_name (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_type - set a mime part's content type

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_type(fetch_mimepart *part, const char *mimetype);
~~~

# DESCRIPTION

fetch_mime_type(3) sets a mime part's content type.

*part* is the part's handle to assign the content type to.

*mimetype* points to the null-terminated file mime type string; it may be
set to NULL to remove a previously attached mime type.

The mime type string is copied into the part, thus the associated storage may
safely be released or reused after call. Setting a part's type multiple times
is valid: only the value set by the last call is retained.

In the absence of a mime type and if needed by the protocol specifications,
a default mime type is determined by the context:

- If set as a custom header, use this value.

- application/form-data for an HTTP form post.

- If a remote filename is set, the mime type is taken from the filename
extension, or application/octet-stream by default.

- For a multipart part, multipart/mixed.

- text/plain in other cases.

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

    /* get data from this file */
    fetch_mime_filedata(part, "image.png");

    /* content-type for this part */
    fetch_mime_type(part, "image/png");

    /* set name */
    fetch_mime_name(part, "image");
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
