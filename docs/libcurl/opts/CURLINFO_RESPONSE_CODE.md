---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_RESPONSE_CODE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_HTTP_CONNECTCODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
  - FTP
  - SMTP
  - LDAP
Added-in: 7.10.8
---

# NAME

FETCHINFO_RESPONSE_CODE - get the last response code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_RESPONSE_CODE, long *codep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the last received HTTP, FTP, SMTP or LDAP
(OpenLDAP only) response code. This option was previously known as
FETCHINFO_HTTP_CODE in libfetch 7.10.7 and earlier. The stored value is zero if
no server response code has been received.

Note that a proxy's CONNECT response should be read with
FETCHINFO_HTTP_CONNECTCODE(3) and not this.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long response_code;
      fetch_easy_getinfo(fetch, FETCHINFO_RESPONSE_CODE, &response_code);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# NOTES

The former name, FETCHINFO_HTTP_CODE, was added in 7.4.1. Support for SMTP
responses added in 7.25.0, for OpenLDAP in 7.81.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
