---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NOBODY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPGET (3)
  - FETCHOPT_MIMEPOST (3)
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_REQUEST_TARGET (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_NOBODY - do the download request without getting the body

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NOBODY, long opt);
~~~

# DESCRIPTION

A long parameter set to 1 tells libfetch to not include the body-part in the
output when doing what would otherwise be a download. For HTTP(S), this makes
libfetch do a HEAD request. For most other protocols it means just not asking
to transfer the body data.

For HTTP operations when FETCHOPT_NOBODY(3) has been set, disabling this
option (with 0) makes it a GET again - only if the method is still set to be
HEAD. The proper way to get back to a GET request is to set
FETCHOPT_HTTPGET(3) and for other methods, use the POST or UPLOAD
options.

Enabling FETCHOPT_NOBODY(3) means asking for a download without a body.

If you do a transfer with HTTP that involves a method other than HEAD, you get
a body (unless the resource and server sends a zero byte body for the specific
URL you request).

# DEFAULT

0, the body is transferred

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* get us the resource without a body - use HEAD */
    fetch_easy_setopt(fetch, FETCHOPT_NOBODY, 1L);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
