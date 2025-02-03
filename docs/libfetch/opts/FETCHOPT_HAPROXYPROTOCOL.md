---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HAPROXYPROTOCOL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
Protocol:
  - All
Added-in: 7.60.0
---

# NAME

FETCHOPT_HAPROXYPROTOCOL - send HAProxy PROXY protocol v1 header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HAPROXYPROTOCOL,
                          long haproxy_protocol);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to send an HAProxy PROXY
protocol v1 header at beginning of the connection. The default action is not to
send this header.

This option is primarily useful when sending test requests to a service that
expects this header.

Most applications do not need this option.

# DEFAULT

0, do not send any HAProxy PROXY protocol header

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_HAPROXYPROTOCOL, 1L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
