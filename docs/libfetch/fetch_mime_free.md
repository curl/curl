---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_mime_free
Section: 3
Source: libfetch
See-also:
  - fetch_free (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

fetch_mime_free - free a previously built mime structure

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_mime_free(fetch_mime *mime);
~~~

# DESCRIPTION

fetch_mime_free(3) is used to clean up data previously built/appended
with fetch_mime_addpart(3) and other mime-handling functions. This must
be called when the data has been used, which typically means after
fetch_easy_perform(3) has been called.

The handle to free is the one you passed to the FETCHOPT_MIMEPOST(3)
option: attached sub part mime structures must not be explicitly freed as they
are by the top structure freeing.

**mime** is the handle as returned from a previous call to
fetch_mime_init(3) and may be NULL.

Passing in a NULL pointer in *mime* makes this function return immediately
with no action.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* Build the mime message. */
    fetch_mime *mime = fetch_mime_init(fetch);

    /* send off the transfer */

    /* Free multipart message. */
    fetch_mime_free(mime);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

None
