---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_reset
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_duphandle (3)
  - fetch_easy_init (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.12.1
---

# NAME

fetch_easy_reset - reset all options of a libfetch session handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_easy_reset(FETCH *handle);
~~~

# DESCRIPTION

Re-initializes all options previously set on a specified fetch handle to the
default values. This puts back the handle to the same state as it was in when
it was just created with fetch_easy_init(3).

It does not change the following information kept in the handle: live
connections, the Session ID cache, the DNS cache, the cookies, the shares or
the alt-svc cache.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {

    /* ... the handle is used and options are set ... */
    fetch_easy_reset(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Nothing
