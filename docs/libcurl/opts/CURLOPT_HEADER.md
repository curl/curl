---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HEADER
Section: 3
Source: libfetch
Protocol:
  - HTTP
  - FTP
  - IMAP
  - POP3
  - SMTP
See-also:
  - FETCHOPT_HEADERFUNCTION (3)
  - FETCHOPT_HTTPHEADER (3)
Added-in: 7.1
---

# NAME

FETCHOPT_HEADER - pass headers to the data stream

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HEADER, long onoff);
~~~

# DESCRIPTION

Pass the long value *onoff* set to 1 to ask libfetch to include the headers
in the write callback (FETCHOPT_WRITEFUNCTION(3)). This option is
relevant for protocols that actually have headers or other meta-data (like
HTTP and FTP).

When asking to get the headers passed to the same callback as the body, it is
not possible to accurately separate them again without detailed knowledge
about the protocol in use.

Further: the FETCHOPT_WRITEFUNCTION(3) callback is limited to only ever
get a maximum of *FETCH_MAX_WRITE_SIZE* bytes passed to it (16KB), while a
header can be longer and the FETCHOPT_HEADERFUNCTION(3) supports getting
called with headers up to *FETCH_MAX_HTTP_HEADER* bytes big (100KB).

It is often better to use FETCHOPT_HEADERFUNCTION(3) to get the header
data separately.

While named confusingly similar, FETCHOPT_HTTPHEADER(3) is used to set
custom HTTP headers.

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

    fetch_easy_setopt(fetch, FETCHOPT_HEADER, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
