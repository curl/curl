---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MIMEPOST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPOST (3)
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_PUT (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
  - SMTP
  - IMAP
Added-in: 7.56.0
---

# NAME

FETCHOPT_MIMEPOST - send data from mime structure

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

fetch_mime *mime;

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MIMEPOST, mime);
~~~

# DESCRIPTION

Pass a mime handle previously obtained from fetch_mime_init(3).

This setting is supported by the HTTP protocol to post forms and by the
SMTP and IMAP protocols to provide the email data to send/upload.

This option is the preferred way of posting an HTTP form, replacing and
extending the FETCHOPT_HTTPPOST(3) option.

When setting FETCHOPT_MIMEPOST(3) to NULL, libfetch resets the request
type for HTTP to the default to disable the POST. Typically that would mean it
is reset to GET. Instead you should set a desired request method explicitly.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_mime *multipart = fetch_mime_init(fetch);
    if(multipart) {
      fetch_mimepart *part = fetch_mime_addpart(multipart);
      fetch_mime_name(part, "name");
      fetch_mime_data(part, "daniel", FETCH_ZERO_TERMINATED);
      part = fetch_mime_addpart(multipart);
      fetch_mime_name(part, "project");
      fetch_mime_data(part, "fetch", FETCH_ZERO_TERMINATED);
      part = fetch_mime_addpart(multipart);
      fetch_mime_name(part, "logotype-image");
      fetch_mime_filedata(part, "fetch.png");

      /* Set the form info */
      fetch_easy_setopt(fetch, FETCHOPT_MIMEPOST, multipart);

      fetch_easy_perform(fetch); /* post away */
      fetch_mime_free(multipart); /* free the post data */
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
