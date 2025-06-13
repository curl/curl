---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_NETWORK_CHANGED
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_FORBID_REUSE (3)
Protocol:
  - All
Added-in: 8.15.0
---

# NAME

CURLMOPT_NETWORK_CHANGED - signal network changed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_NETWORK_CHANGED,
                            long value);
~~~

# DESCRIPTION

Pass a long for **value**. The set number determines how the multi
handle should adapt to a change in the network.

`1`: do not reuse any existing connection in the multi handle's
connection cache. This closes all connections that are not in use.
Ongoing transfers continue on the connections they operate on.

`2`: in addition to `1` also clear the multi handle's DNS cache.

This option can be set at any time and repeatedly. Any connection created or
DNS information cached afterwards is considered fresh again.

This affects only the connection and DNS cache of the multi handle and
not the ones owned by SHARE handles.

# DEFAULT

0, which means that there was no change.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* do transfers on the multi handle */
  /* do not reuse existing connections */
  curl_multi_setopt(m, CURLMOPT_NETWORK_CHANGED, 1L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
