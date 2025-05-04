---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_CONNCACHE_STALE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FRESH_CONNECT (3)
  - CURLINFO_NUM_CONNECTS (3)
Protocol:
  - HTTP
Added-in: 8.14.0
---

# NAME

CURLMOPT_CONNCACHE_STALE - mark connections in the cache as stale in order to
not reuse them

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_CONNCACHE_STALE,
                            long stale);
~~~

# DESCRIPTION

A parameter set to 1 tells libcurl not to reuse existing connections in pool.
This option is intended to adjust to network changes, and prevent the reuse of
invalid connections that were created in the old network.

When setting CURLMOPT_CONNCACHE_STALE(3) to 1, libcurl will ignore all
connections in pool that were created earlier than the 'current time', in order
to prevent their reuse. After CURLMOPT_CONNCACHE_STALE(3) to 1, libcurl will
create new connections for future requests, and also try reusing them until the
next setting of CURLMOPT_CONNCACHE_STALE(3) to 1.

If CURLMOPT_CONNCACHE_STALE(3) is set to 1 multiple times, libcurl will update
the 'current time' value for checking stale.

When setting CURLMOPT_CONNCACHE_STALE(3) to 0, libcurl will always attempt to
reuse the connections in the pool by default.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *multi_handle = curl_multi_init();
  /* not reuse existing connections in pool from now */
  curl_multi_setopt(multi_handle, CURLMOPT_CONNCACHE_STALE, 1L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred,
see libcurl-errors(3).
