---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TRANSFERTEXT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CRLF (3)
Protocol:
  - All
Added-in: 7.1.1
---

# NAME

FETCHOPT_TRANSFERTEXT - request a text based transfer for FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TRANSFERTEXT, long text);
~~~

# DESCRIPTION

A parameter set to 1 tells the library to use ASCII mode for FTP transfers,
instead of the default binary transfer. For Win32 systems it does not set the
stdout to binary mode. This option can be usable when transferring text data
between systems with different views on certain characters, such as newlines
or similar.

libfetch does not do a complete ASCII conversion when doing ASCII transfers
over FTP. This is a known limitation/flaw that nobody has rectified. libfetch
simply sets the mode to ASCII and performs a standard transfer.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/textfile");
    fetch_easy_setopt(fetch, FETCHOPT_TRANSFERTEXT, 1L);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
