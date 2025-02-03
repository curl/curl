---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PIPEWAIT
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_MAX_HOST_CONNECTIONS (3)
  - FETCHMOPT_PIPELINING (3)
  - FETCHOPT_FORBID_REUSE (3)
  - FETCHOPT_FRESH_CONNECT (3)
Protocol:
  - HTTP
Added-in: 7.43.0
---

# NAME

FETCHOPT_PIPEWAIT - wait for multiplexing

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PIPEWAIT, long wait);
~~~

# DESCRIPTION

Set *wait* to 1L to tell libfetch to prefer to wait for a connection to
confirm or deny that it can do multiplexing before continuing.

When about to perform a new transfer that allows multiplexing, libfetch checks
for existing connections to use. If no such connection exists it immediately
continues and creates a fresh new connection to use.

By setting this option to 1 - and having FETCHMOPT_PIPELINING(3) enabled
for the multi handle this transfer is associated with - libfetch instead waits
for the connection to reveal if it is possible to multiplex on before it
continues. This enables libfetch to much better keep the number of connections
to a minimum when using multiplexing protocols.

With this option set, libfetch prefers to wait and reuse an existing connection
for multiplexing rather than the opposite: prefer to open a new connection
rather than waiting.

The waiting time is as long as it takes for the connection to get up and for
libfetch to get the necessary response back that informs it about its protocol
and support level.

# DEFAULT

0 (off)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PIPEWAIT, 1L);

    /* now add this easy handle to the multi handle */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
