---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_TRANSFER_MODE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CRLF (3)
  - FETCHOPT_HTTPPROXYTUNNEL (3)
  - FETCHOPT_PROXY (3)
  - FETCHOPT_TRANSFERTEXT (3)
Protocol:
    - All
Added-in: 7.18.0
---

# NAME

FETCHOPT_PROXY_TRANSFER_MODE - append FTP transfer mode to URL for proxy

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_TRANSFER_MODE,
                          long enabled);
~~~

# DESCRIPTION

Pass a long. If the value is set to 1 (one), it tells libfetch to set the
transfer mode (binary or ASCII) for FTP transfers done via an HTTP proxy, by
appending ;type=a or ;type=i to the URL. Without this setting, or it being set
to 0 (zero, the default), FETCHOPT_TRANSFERTEXT(3) has no effect when
doing FTP via a proxy. Beware that not all proxies support this feature.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://example.com/old-server/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://localhost:80");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_TRANSFER_MODE, 1L);
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
