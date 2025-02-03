---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_XFER_ID
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONN_ID (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 8.2.0
---

# NAME

FETCHINFO_XFER_ID - get the ID of a transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_XFER_ID,
                           fetch_off_t *xfer_id);
~~~

# DESCRIPTION

Pass a pointer to a *fetch_off_t* to receive the identifier of the
current/last transfer done with the handle. Stores -1 if no transfer
has been started yet for the handle.

The transfer id is unique among all transfers performed using the same
connection cache. This is implicitly the case for all transfers in the
same multi handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Perform the request */
    res = fetch_easy_perform(fetch);

    if(!res) {
      fetch_off_t xfer_id;
      res = fetch_easy_getinfo(fetch, FETCHINFO_XFER_ID, &xfer_id);
      if(!res) {
        printf("Transfer ID: %" FETCH_FORMAT_FETCH_OFF_T "\n", xfer_id);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
