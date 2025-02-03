---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MIME_OPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPOST (3)
  - FETCHOPT_MIMEPOST (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.81.0
---

# NAME

FETCHOPT_MIME_OPTIONS - set MIME option flags

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MIME_OPTIONS, long options);
~~~

# DESCRIPTION

Pass a long that holds a bitmask of FETCHMIMEOPT_* defines. Each bit is a
Boolean flag used while encoding a MIME tree or multipart form data.

Available bits are:

## FETCHMIMEOPT_FORMESCAPE

Tells libfetch to escape multipart form field and filenames using the
backslash-escaping algorithm rather than percent-encoding (HTTP only).

Backslash-escaping consists in preceding backslashes and double quotes with
a backslash. Percent encoding maps all occurrences of double quote,
carriage return and line feed to %22, %0D and %0A respectively.

Before version 7.81.0, percent-encoding was never applied.

HTTP browsers used to do backslash-escaping in the past but have over time
transitioned to use percent-encoding. This option allows one to address
server-side applications that have not yet have been converted.

As an example, consider field or filename *strangename"kind*. When the
containing multipart form is sent, this is normally transmitted as
*strangename%22kind*. When this option is set, it is sent as
*strangename"kind*.

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  fetch_mime *form = NULL;

  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_MIME_OPTIONS, FETCHMIMEOPT_FORMESCAPE);

    form = fetch_mime_init(fetch);
    if(form) {
      fetch_mimepart *part = fetch_mime_addpart(form);

      if(part) {
        fetch_mime_filedata(part, "strange\\file\\name");
        fetch_mime_name(part, "strange\"field\"name");
        fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, form);

        /* Perform the request */
        fetch_easy_perform(fetch);
      }
    }

    fetch_easy_cleanup(fetch);
    fetch_mime_free(form);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
