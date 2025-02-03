---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DNS_USE_GLOBAL_CACHE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DNS_CACHE_TIMEOUT (3)
  - FETCHOPT_SHARE (3)
Protocol:
  - All
Added-in: 7.9.3
---

# NAME

FETCHOPT_DNS_USE_GLOBAL_CACHE - global DNS cache

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DNS_USE_GLOBAL_CACHE,
                          long enable);
~~~

# DESCRIPTION

Has no function since 7.62.0. Do not use.

Pass a long. If the *enable* value is 1, it tells fetch to use a global DNS
cache that survives between easy handle creations and deletions. This is not
thread-safe and this uses a global variable.

See FETCHOPT_SHARE(3) and fetch_share_init(3) for the correct way to share DNS
cache between transfers.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* switch off the use of a global, thread unsafe, cache */
    fetch_easy_setopt(fetch, FETCHOPT_DNS_USE_GLOBAL_CACHE, 0L);
    ret = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}

~~~

# DEPRECATED

Deprecated since 7.11.1. Functionality removed in 7.62.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
