---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NOSIGNAL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

FETCHOPT_NOSIGNAL - skip all signal handling

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NOSIGNAL, long onoff);
~~~

# DESCRIPTION

If *onoff* is 1, libfetch uses no functions that install signal handlers or
any functions that cause signals to be sent to the process. This option is
here to allow multi-threaded Unix applications to still set/use all timeout
options etc, without risking getting signals.

If this option is set and libfetch has been built with the standard name
resolver, timeouts cannot occur while the name resolve takes place. Consider
building libfetch with the c-ares or threaded resolver backends to enable
asynchronous DNS lookups, to enable timeouts for name resolves without the use
of signals.

Setting FETCHOPT_NOSIGNAL(3) to 1 makes libfetch NOT ask the system to
ignore SIGPIPE signals, which otherwise are sent by the system when trying to
send data to a socket which is closed in the other end. libfetch makes an
effort to never cause such SIGPIPE signals to trigger, but some operating
systems have no way to avoid them and even on those that have there are some
corner cases when they may still happen, contrary to our desire.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");

    fetch_easy_setopt(fetch, FETCHOPT_NOSIGNAL, 1L);

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
