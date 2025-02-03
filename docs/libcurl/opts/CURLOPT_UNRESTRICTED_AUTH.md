---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_UNRESTRICTED_AUTH
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - FETCHOPT_MAXREDIRS (3)
  - FETCHOPT_REDIR_PROTOCOLS_STR (3)
  - FETCHOPT_USERPWD (3)
Protocol:
  - HTTP
Added-in: 7.10.4
---

# NAME

FETCHOPT_UNRESTRICTED_AUTH - send credentials to other hosts too

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_UNRESTRICTED_AUTH,
                          long goahead);
~~~

# DESCRIPTION

Set the long *gohead* parameter to 1L to make libfetch continue to send
authentication (user+password) credentials or explicitly set cookie headers
when following locations, even when the host changes. This option is
meaningful only when setting FETCHOPT_FOLLOWLOCATION(3).

Further, when this option is not used or set to **0L**, libfetch does not send
custom nor internally generated `Authentication:` or `Cookie:` headers on
requests done to other hosts than the one used for the initial URL. Another
host means that one or more of hostname, protocol scheme or port number
changed.

By default, libfetch only sends `Authentication:` or explicitly set `Cookie:`
headers to the initial host as given in the original URL, to avoid leaking
username + password to other sites.

This option should be used with caution: when fetch follows redirects it
blindly fetches the next URL as instructed by the server. Setting
FETCHOPT_UNRESTRICTED_AUTH(3) to 1L makes fetch trust the server and sends
possibly sensitive credentials to any host the server points to, possibly
again and again as the following hosts can keep redirecting to new hosts.

Due to the way HTTP works, almost any header can be made to contain data a
client may not want to pass on to other servers than the initially intended
host and for all other headers than the two mentioned above, there is no
protection from this happening when libfetch is told to follow redirects.

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
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_UNRESTRICTED_AUTH, 1L);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
