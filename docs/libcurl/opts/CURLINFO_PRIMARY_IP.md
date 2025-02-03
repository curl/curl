---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PRIMARY_IP
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_LOCAL_IP (3)
  - FETCHINFO_LOCAL_PORT (3)
  - FETCHINFO_PRIMARY_PORT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.19.0
---

# NAME

FETCHINFO_PRIMARY_IP - get IP address of last connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PRIMARY_IP, char **ip);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the IP address of the most recent connection done with this
**fetch** handle. This string may be IPv6 when that is enabled. Note that you
get a pointer to a memory area that is reused at next request so you need to
copy the string if you want to keep the information.

The **ip** pointer is NULL or points to private memory. You MUST NOT free - it
gets freed when you call fetch_easy_cleanup(3) on the corresponding fetch
handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  char *ip;
  FETCHcode res;
  FETCH *fetch = fetch_easy_init();

  fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

  /* Perform the transfer */
  res = fetch_easy_perform(fetch);
  /* Check for errors */
  if((res == FETCHE_OK) &&
     !fetch_easy_getinfo(fetch, FETCHINFO_PRIMARY_IP, &ip) && ip) {
    printf("IP: %s\n", ip);
  }

  /* always cleanup */
  fetch_easy_cleanup(fetch);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
