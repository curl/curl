---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TRANSFER_ENCODING
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ACCEPT_ENCODING (3)
  - FETCHOPT_HTTP_TRANSFER_DECODING (3)
Protocol:
  - HTTP
Added-in: 7.21.6
---

# NAME

FETCHOPT_TRANSFER_ENCODING - ask for HTTP Transfer Encoding

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TRANSFER_ENCODING,
                          long enable);
~~~

# DESCRIPTION

Pass a long set to 1L to *enable* or 0 to disable.

Adds a request for compressed Transfer Encoding in the outgoing HTTP
request. If the server supports this and so desires, it can respond with the
HTTP response sent using a compressed Transfer-Encoding that is automatically
uncompressed by libfetch on reception.

Transfer-Encoding differs slightly from the Content-Encoding you ask for with
FETCHOPT_ACCEPT_ENCODING(3) in that a Transfer-Encoding is strictly meant
to be for the transfer and thus MUST be decoded before the data arrives in the
client. Traditionally, Transfer-Encoding has been much less used and supported
by both HTTP clients and HTTP servers.

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
    fetch_easy_setopt(fetch, FETCHOPT_TRANSFER_ENCODING, 1L);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
