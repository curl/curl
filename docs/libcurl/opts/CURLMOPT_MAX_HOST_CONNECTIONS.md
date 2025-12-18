---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_MAX_HOST_CONNECTIONS
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_MAXCONNECTS (3)
  - CURLMOPT_MAX_TOTAL_CONNECTIONS (3)
Protocol:
  - All
Added-in: 7.30.0
---

# NAME

CURLMOPT_MAX_HOST_CONNECTIONS - max number of connections to a single host

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_MAX_HOST_CONNECTIONS,
                            long max);
~~~

# DESCRIPTION

Pass a long to indicate **max**, the maximum amount of simultaneously open
connections libcurl may hold a single host (a host being the same as a
hostname + port number pair). For each new transfer to the same host, libcurl
might open a new connection up to the limit set by
CURLMOPT_MAX_HOST_CONNECTIONS(3). When the limit is reached, new sessions are
kept pending until a connection becomes available.

The default **max** value is 0, unlimited. This set limit is also used for
proxy connections, and then the proxy is considered to be the host for which
this limit counts.

When more transfers are added to the multi handle than what can be performed
due to the set limit, they are queued up waiting for their chance.

While a transfer is queued up internally waiting for a connection, the
CURLOPT_TIMEOUT_MS(3) timeout is counted inclusive of the waiting time,
meaning that if you set a too narrow timeout the transfer might never even
start before it times out. The CURLOPT_CONNECTTIMEOUT_MS(3) time is also
similarly still treated as a per-connect timeout and might expire even before
making a new connection is permitted.

Changing this value while there are transfers in progress is possible. The new
value is then used the next time checks are performed. Lowering the value does
not close down any active transfers, it simply does not allow new ones to get
made.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* do no more than 2 connections per host */
  curl_multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 2L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
