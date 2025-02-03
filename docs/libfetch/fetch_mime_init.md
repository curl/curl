---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_init
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MIMEPOST (3)
  - fetch_mime_addpart (3)
  - fetch_mime_free (3)
  - fetch_mime_subparts (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_init - create a mime handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

fetch_mime *fetch_mime_init(FETCH *easy_handle);
~~~

# DESCRIPTION

fetch_mime_init(3) creates a handle to a new empty mime structure.
This mime structure can be subsequently filled using the mime API, then
attached to some easy handle using option FETCHOPT_MIMEPOST(3) within
a fetch_easy_setopt(3) call or added as a multipart in another mime
handle's part using fetch_mime_subparts(3).

*easy_handle* is used for part separator randomization and error
reporting. Since 7.87.0, it does not need to be the final target handle.

Using a mime handle is the recommended way to post an HTTP form, format and
send a multi-part email with SMTP or upload such an email to an IMAP server.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *easy = fetch_easy_init();
  fetch_mime *mime;
  fetch_mimepart *part;

  /* Build an HTTP form with a single field named "data", */
  mime = fetch_mime_init(easy);
  part = fetch_mime_addpart(mime);
  fetch_mime_data(part, "This is the field data", FETCH_ZERO_TERMINATED);
  fetch_mime_name(part, "data");

  /* Post and send it. */
  fetch_easy_setopt(easy, FETCHOPT_MIMEPOST, mime);
  fetch_easy_setopt(easy, FETCHOPT_URL, "https://example.com");
  fetch_easy_perform(easy);

  /* Clean-up. */
  fetch_easy_cleanup(easy);
  fetch_mime_free(mime);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A mime struct handle, or NULL upon failure.
