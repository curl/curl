---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SSL_VERIFYRESULT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PROXY_SSL_VERIFYRESULT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.5
---

# NAME

FETCHINFO_SSL_VERIFYRESULT - get the result of the certificate verification

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SSL_VERIFYRESULT,
                           long *result);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the result of the server SSL certificate
verification that was requested (using the FETCHOPT_SSL_VERIFYPEER(3)
option).

0 is a positive result. Non-zero is an error.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    long verifyresult;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    res = fetch_easy_perform(fetch);
    if(res) {
      printf("error: %s\n", fetch_easy_strerror(res));
      fetch_easy_cleanup(fetch);
      return 1;
    }

    res = fetch_easy_getinfo(fetch, FETCHINFO_SSL_VERIFYRESULT,
                            &verifyresult);
    if(!res) {
      printf("The peer verification said %s\n",
             (verifyresult ? "bad" : "fine"));
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
