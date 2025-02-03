---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HEADEROPT
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_PROXYHEADER (3)
Added-in: 7.37.0
---

# NAME

FETCHOPT_HEADEROPT - send HTTP headers to both proxy and host or separately

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HEADEROPT, long bitmask);
~~~

# DESCRIPTION

Pass a long that is a bitmask of options of how to deal with headers. The two
mutually exclusive options are:

**FETCHHEADER_UNIFIED** - the headers specified in
FETCHOPT_HTTPHEADER(3) are used in requests both to servers and
proxies. With this option enabled, FETCHOPT_PROXYHEADER(3) does not have
any effect.

**FETCHHEADER_SEPARATE** - makes FETCHOPT_HTTPHEADER(3) headers only get
sent to a server and not to a proxy. Proxy headers must be set with
FETCHOPT_PROXYHEADER(3) to get used. Note that if a non-CONNECT request
is sent to a proxy, libfetch sends both server headers and proxy headers. When
doing CONNECT, libfetch sends FETCHOPT_PROXYHEADER(3) headers only to the
proxy and then FETCHOPT_HTTPHEADER(3) headers only to the server.

# DEFAULT

FETCHHEADER_SEPARATE (changed in 7.42.1, used FETCHHEADER_UNIFIED before then)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    struct fetch_slist *list;
    list = fetch_slist_append(NULL, "Shoesize: 10");
    list = fetch_slist_append(list, "Accept:");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://localhost:8080");
    fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, list);

    /* HTTPS over a proxy makes a separate CONNECT to the proxy, so tell
       libfetch to not send the custom headers to the proxy. Keep them
       separate. */
    fetch_easy_setopt(fetch, FETCHOPT_HEADEROPT, FETCHHEADER_SEPARATE);
    ret = fetch_easy_perform(fetch);
    fetch_slist_free_all(list);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
