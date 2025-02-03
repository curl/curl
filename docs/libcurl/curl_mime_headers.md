---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_headers
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_name (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_headers - set a mime part's custom headers

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_headers(fetch_mimepart *part,
                           struct fetch_slist *headers, int take_ownership);
~~~

# DESCRIPTION

fetch_mime_headers(3) sets a mime part's custom headers.

*part* is the part's handle to assign the custom headers list to.

*headers* is the head of a list of custom headers; it may be set to NULL
to remove a previously attached custom header list.

*take_ownership*: when non-zero, causes the list to be freed upon
replacement or mime structure deletion; in this case the list must not be
freed explicitly.

Setting a part's custom headers list multiple times is valid: only the value
set by the last call is retained.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct fetch_slist *headers = NULL;
  FETCH *easy = fetch_easy_init();
  fetch_mime *mime;
  fetch_mimepart *part;

  headers = fetch_slist_append(headers, "Custom-Header: mooo");

  mime = fetch_mime_init(easy);
  part = fetch_mime_addpart(mime);

  /* use these headers in the part, takes ownership */
  fetch_mime_headers(part, headers, 1);

  /* pass on this data */
  fetch_mime_data(part, "12345679", FETCH_ZERO_TERMINATED);

  /* set name */
  fetch_mime_name(part, "numbers");

  /* Post and send it. */
  fetch_easy_setopt(easy, FETCHOPT_MIMEPOST, mime);
  fetch_easy_setopt(easy, FETCHOPT_URL, "https://example.com");
  fetch_easy_perform(easy);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
