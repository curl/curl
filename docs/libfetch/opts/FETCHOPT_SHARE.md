---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SHARE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COOKIE (3)
  - FETCHSHOPT_SHARE (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

FETCHOPT_SHARE - share handle to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SHARE, FETCHSH *share);
~~~

# DESCRIPTION

Pass a *share* handle as a parameter. The share handle must have been
created by a previous call to fetch_share_init(3). Setting this option,
makes this fetch handle use the data from the shared handle instead of keeping
the data to itself. This enables several fetch handles to share data. If the
fetch handles are used simultaneously in multiple threads, you **MUST** use
the locking methods in the share handle. See fetch_share_setopt(3) for
details.

If you add a share that is set to share cookies, your easy handle uses that
cookie cache and get the cookie engine enabled. If you stop sharing an object
that was using cookies (or change to another object that does not share
cookies), the easy handle gets its cookie engine disabled.

Data that the share object is not set to share is dealt with the usual way, as
if no share was used.

Set this option to NULL again to stop using that share object.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  FETCH *fetch2 = fetch_easy_init(); /* a second handle */
  if(fetch) {
    FETCHcode res;
    FETCHSH *shobject = fetch_share_init();
    fetch_share_setopt(shobject, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "");
    fetch_easy_setopt(fetch, FETCHOPT_SHARE, shobject);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);

    /* the second handle shares cookies from the first */
    fetch_easy_setopt(fetch2, FETCHOPT_URL, "https://example.com/second");
    fetch_easy_setopt(fetch2, FETCHOPT_COOKIEFILE, "");
    fetch_easy_setopt(fetch2, FETCHOPT_SHARE, shobject);
    res = fetch_easy_perform(fetch2);
    fetch_easy_cleanup(fetch2);

    fetch_share_cleanup(shobject);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
