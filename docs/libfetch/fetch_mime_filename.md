---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_filename
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_data (3)
  - fetch_mime_filedata (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_filename - set a mime part's remote filename

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_filename(fetch_mimepart *part,
                            const char *filename);
~~~

# DESCRIPTION

fetch_mime_filename(3) sets a mime part's remote filename. When remote
filename is set, content data is processed as a file, whatever is the part's
content source. A part's remote filename is transmitted to the server in the
associated Content-Disposition generated header.

*part* is the part's handle to assign the remote filename to.

*filename* points to the null-terminated filename string; it may be set
to NULL to remove a previously attached remote filename.

The remote filename string is copied into the part, thus the associated
storage may safely be released or reused after call. Setting a part's file
name multiple times is valid: only the value set by the last call is retained.

# %PROTOCOLS%

# EXAMPLE

~~~c

static char imagebuf[]="imagedata";

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

    /* send image data from memory */
    fetch_mime_data(part, imagebuf, sizeof(imagebuf));

    /* set a file name to make it look like a file upload */
    fetch_mime_filename(part, "image.png");

    /* set name */
    fetch_mime_name(part, "data");
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
