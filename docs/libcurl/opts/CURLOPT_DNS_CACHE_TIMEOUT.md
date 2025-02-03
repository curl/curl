---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DNS_CACHE_TIMEOUT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECTTIMEOUT_MS (3)
  - FETCHOPT_DNS_SERVERS (3)
  - FETCHOPT_DNS_USE_GLOBAL_CACHE (3)
  - FETCHOPT_MAXAGE_CONN (3)
  - FETCHOPT_RESOLVE (3)
Protocol:
  - All
Added-in: 7.9.3
---

# NAME

FETCHOPT_DNS_CACHE_TIMEOUT - life-time for DNS cache entries

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DNS_CACHE_TIMEOUT, long age);
~~~

# DESCRIPTION

Pass a long, this sets the timeout in seconds. Name resolve results are kept
in memory and used for this number of seconds. Set to zero to completely
disable caching, or set to -1 to make the cached entries remain forever. By
default, libfetch caches this info for 60 seconds.

We recommend users not to tamper with this option unless strictly necessary.
If you do, be careful of using large values that can make the cache size grow
significantly if many different hostnames are used within that timeout period.

The name resolve functions of various libc implementations do not re-read name
server information unless explicitly told so (for example, by calling
*res_init(3)*). This may cause libfetch to keep using the older server even
if DHCP has updated the server info, and this may look like a DNS cache issue
to the casual libfetch-app user.

DNS entries have a "TTL" property but libfetch does not use that. This DNS
cache timeout is entirely speculative that a name resolves to the same address
for a small amount of time into the future.

Since version 8.1.0, libfetch prunes entries from the DNS cache if it exceeds
30,000 entries no matter which timeout value is used.

# DEFAULT

60

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* only reuse addresses for a short time */
    fetch_easy_setopt(fetch, FETCHOPT_DNS_CACHE_TIMEOUT, 2L);

    res = fetch_easy_perform(fetch);

    /* in this second request, the cache is not be used if more than
       two seconds have passed since the previous name resolve */
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
