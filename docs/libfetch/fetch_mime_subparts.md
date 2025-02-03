---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_subparts
Section: 3
Source: libfetch
See-also:
  - fetch_mime_addpart (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_subparts - set sub-parts of a multipart mime part

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_mime_subparts(fetch_mimepart *part, fetch_mime *subparts);
~~~

# DESCRIPTION

fetch_mime_subparts(3) sets a multipart mime part's content from a mime
structure.

*part* is a handle to the multipart part.

*subparts* is a mime structure handle holding the sub-parts. After
fetch_mime_subparts(3) succeeds, the mime structure handle belongs to the
multipart part and must not be freed explicitly. It may however be updated by
subsequent calls to mime API functions.

Setting a part's contents multiple times is valid: only the value set by the
last call is retained. It is possible to unassign previous part's contents by
setting *subparts* to NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c

static char *inline_html = "<title>example</title>";
static char *inline_text = "once upon the time";

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_slist *slist;

    /* The inline part is an alternative proposing the html and the text
       versions of the email. */
    fetch_mime *alt = fetch_mime_init(fetch);
    fetch_mimepart *part;

    /* HTML message. */
    part = fetch_mime_addpart(alt);
    fetch_mime_data(part, inline_html, FETCH_ZERO_TERMINATED);
    fetch_mime_type(part, "text/html");

    /* Text message. */
    part = fetch_mime_addpart(alt);
    fetch_mime_data(part, inline_text, FETCH_ZERO_TERMINATED);

    /* Create the inline part. */
    part = fetch_mime_addpart(alt);
    fetch_mime_subparts(part, alt);
    fetch_mime_type(part, "multipart/alternative");
    slist = fetch_slist_append(NULL, "Content-Disposition: inline");
    fetch_mime_headers(part, slist, 1);
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
