---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CONN_ID
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_XFER_ID (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 8.2.0
---

# NAME

FETCHINFO_CONN_ID - get the ID of the last connection used by the handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CONN_ID,
                           fetch_off_t *conn_id);
~~~

# DESCRIPTION

Pass a pointer to a *fetch_off_t* to receive the connection identifier last
used by the handle. Stores -1 if there was no connection used.

The connection id is unique among all connections using the same
connection cache. This is implicitly the case for all connections in the
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
      fetch_off_t conn_id;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONN_ID, &conn_id);
      if(!res) {
        printf("Connection used: %" FETCH_FORMAT_FETCH_OFF_T "\n", conn_id);
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
