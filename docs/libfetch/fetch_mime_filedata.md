---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_filedata
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_data (3)
  - fetch_mime_filename (3)
  - fetch_mime_name (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_filedata - set a mime part's body data from a file contents

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_filedata(fetch_mimepart *part,
                            const char *filename);
~~~

# DESCRIPTION

fetch_mime_filedata(3) sets a mime part's body content from the named
file's contents. This is an alternative to fetch_mime_data(3) for setting
data to a mime part.

*part* is the part's to assign contents to.

*filename* points to the null-terminated file's path name. The pointer can
be NULL to detach the previous part contents settings. Filename storage can
be safely be reused after this call.

As a side effect, the part's remote filename is set to the base name of the
given *filename* if it is a valid named file. This can be undone or
overridden by a subsequent call to fetch_mime_filename(3).

The contents of the file is read during the file transfer in a streaming
manner to allow huge files to get transferred without using much memory. It
therefore requires that the file is kept intact during the entire request.

If the file size cannot be determined before actually reading it (such as for
a character device or named pipe), the whole mime structure containing the
part is transferred using chunks by HTTP but is rejected by IMAP.

Setting a part's contents multiple times is valid: only the value set by the
last call is retained.

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

    /* send data from this file */
    fetch_mime_filedata(part, "image.png");

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

FETCHE_READ_ERROR is only an indication that the file is not yet readable: it
can be safely ignored at this time, but the file must be made readable before
the pertaining easy handle is performed.
