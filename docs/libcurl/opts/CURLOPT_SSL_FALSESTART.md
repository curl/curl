---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_FALSESTART
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TCP_FASTOPEN (3)
Protocol:
  - TLS
TLS-backend:
  - Secure Transport
Added-in: 7.42.0
---

# NAME

FETCHOPT_SSL_FALSESTART - TLS false start

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_FALSESTART, long enable);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0 to disable.

This option determines whether libfetch should use false start during the TLS
handshake. False start is a mode where a TLS client starts sending application
data before verifying the server's Finished message, thus saving a round trip
when performing a full handshake.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_SSL_FALSESTART, 1L);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
