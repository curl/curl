---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_LOCAL_PORT
Section: 3
Source: libfetch
Protocol:
  - TCP
  - QUIC
See-also:
  - FETCHINFO_LOCAL_IP (3)
  - FETCHINFO_PRIMARY_PORT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Added-in: 7.21.0
---

# NAME

FETCHINFO_LOCAL_PORT - get the latest local port number

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_LOCAL_PORT, long *portp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the local port number of the most recent
connection done with this **fetch** handle.

If the connection was done using QUIC, the port number is a UDP port number,
otherwise it is a TCP port number.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);

    if(FETCHE_OK == res) {
      long port;
      res = fetch_easy_getinfo(fetch, FETCHINFO_LOCAL_PORT, &port);

      if(FETCHE_OK == res) {
        printf("We used local port: %ld\n", port);
      }
    }
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
