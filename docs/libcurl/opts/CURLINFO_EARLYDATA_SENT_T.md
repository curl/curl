---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_EARLYDATA_SENT_T
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
Added-in: 8.11.0
---

# NAME

FETCHINFO_EARLYDATA_SENT_T - get the number of bytes sent as TLS early data

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_EARLYDATA_SENT_T,
                           fetch_off_t *amount);
~~~

# DESCRIPTION

Pass a pointer to an *fetch_off_t* to receive the total amount of bytes that
were sent to the server as TLSv1.3 early data. When no TLS early
data is used, this reports 0.

TLS early data is only attempted when FETCHSSLOPT_EARLYDATA is set for the
transfer. In addition, it is only used by libfetch when a TLS session exists
that announces support.

The amount is **negative** when the sent data was rejected
by the server. TLS allows a server that announces support for early data to
reject any attempt to use it at its own discretion. When for example 127
bytes had been sent, but were rejected, it reports -127 as the amount "sent".

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
      fetch_off_t amount;
      res = fetch_easy_getinfo(fetch, FETCHINFO_EARLYDATA_SENT_T, &amount);
      if(!res) {
        printf("TLS earlydata: %" FETCH_FORMAT_FETCH_OFF_T " bytes\n", amount);
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
