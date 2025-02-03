---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CAPATH
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CAINFO (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - wolfSSL
Added-in: 7.84.0
---

# NAME

FETCHINFO_CAPATH - get the default built-in CA path string

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CAPATH, char **path);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the default built-in path used for the FETCHOPT_CAPATH(3)
option unless set by the user.

Note that in a situation where libfetch has been built to support multiple TLS
libraries, this option might return a string even if the specific TLS library
currently set to be used does not support FETCHOPT_CAPATH(3).

This is a path identifying a directory.

The **path** pointer is set to NULL if there is no default path.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    char *capath = NULL;
    fetch_easy_getinfo(fetch, FETCHINFO_CAPATH, &capath);
    if(capath) {
      printf("default ca path: %s\n", capath);
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
