---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_POSTREDIR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_EFFECTIVE_METHOD (3)
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - FETCHOPT_MAXREDIRS (3)
  - FETCHOPT_POSTFIELDS (3)
Protocol:
  - HTTP
Added-in: 7.19.1
---

# NAME

FETCHOPT_POSTREDIR - how to act on an HTTP POST redirect

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_POSTREDIR,
                          long bitmask);
~~~

# DESCRIPTION

Pass a bitmask to control how libfetch acts on redirects after POSTs that get a
301, 302 or 303 response back. A parameter with bit 0 set (value
**FETCH_REDIR_POST_301**) tells the library to respect RFC 7231 (section
6.4.2 to 6.4.4) and not convert POST requests into GET requests when following
a 301 redirection. Setting bit 1 (value **FETCH_REDIR_POST_302**) makes
libfetch maintain the request method after a 302 redirect whilst setting bit 2
(value **FETCH_REDIR_POST_303**) makes libfetch maintain the request method
after a 303 redirect. The value **FETCH_REDIR_POST_ALL** is a convenience
define that sets all three bits.

The non-RFC behavior is ubiquitous in web browsers, so the library does the
conversion by default to maintain consistency. However, a server may require a
POST to remain a POST after such a redirection. This option is meaningful only
when setting FETCHOPT_FOLLOWLOCATION(3).

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

    /* a silly POST example */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, "data=true");

    /* example.com is redirected, so we tell libfetch to send POST on 301,
       302 and 303 HTTP response codes */
    fetch_easy_setopt(fetch, FETCHOPT_POSTREDIR, FETCH_REDIR_POST_ALL);

    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_POST301 up to 7.19.0 as it only supported the
301 then. FETCH_REDIR_POST_303 was added in 7.26.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
