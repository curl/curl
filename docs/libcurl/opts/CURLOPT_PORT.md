---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PORT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRIMARY_PORT (3)
  - FETCHOPT_STDERR (3)
  - FETCHOPT_URL (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_PORT - remote port number to connect to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PORT, long number);
~~~

# DESCRIPTION

We discourage using this option since its scope is not obvious and hard to
predict. Set the preferred port number in the URL instead.

This option sets *number* to be the remote port number to connect to,
instead of the one specified in the URL or the default port for the used
protocol.

Usually, you just let the URL decide which port to use but this allows the
application to override that.

While this option accepts a 'long', a port number is an unsigned 16 bit number
and therefore using a port number lower than zero or over 65535 causes a
**FETCHE_BAD_FUNCTION_ARGUMENT** error.

# DEFAULT

0 which makes it not used. This also makes port number zero impossible to set
with this API.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_PORT, 8080L);
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
