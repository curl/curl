---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FETCHU
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_URL (3)
  - fetch_url (3)
  - fetch_url_cleanup (3)
  - fetch_url_dup (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: 7.63.0
---

# NAME

FETCHOPT_FETCHU - URL in URL handle format

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FETCHU, FETCHU *pointer);
~~~

# DESCRIPTION

Pass in a pointer to the *URL* handle to work with. The parameter should be a
*FETCHU pointer*. Setting FETCHOPT_FETCHU(3) explicitly overrides
FETCHOPT_URL(3).

FETCHOPT_URL(3) or FETCHOPT_FETCHU(3) **must** be set before a
transfer is started.

libfetch uses this handle and its contents read-only and does not change its
contents. An application can update the contents of the URL handle after a
transfer is done and if the same handle is used in a subsequent request the
updated contents is used.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  FETCHU *urlp = fetch_url();
  if(fetch) {
    FETCHcode res;
    FETCHUcode ret;
    ret = fetch_url_set(urlp, FETCHUPART_URL, "https://example.com", 0);

    fetch_easy_setopt(fetch, FETCHOPT_FETCHU, urlp);

    res = fetch_easy_perform(fetch);

    fetch_url_cleanup(urlp);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
