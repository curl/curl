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

Pass a long to indicate **max**. The set number is used as the maximum amount
of simultaneously open connections to a single host (a host being the same as
a hostname + port number pair). For each new session to a host, libcurl might
open a new connection up to the limit set by CURLMOPT_MAX_HOST_CONNECTIONS(3).
When the limit is reached, new sessions are kept pending until a connection
becomes available.

The default **max** value is 0, unlimited. This set limit is also used for
proxy connections, and then the proxy is considered to be the host for which
this limit counts.

When more transfers are added to the multi handle than what can be performed
due to the set limit, they are queued up waiting for their chance. When that
happens, the CURLOPT_TIMEOUT_MS(3) timeout is inclusive of the waiting time,
meaning that if you set a too narrow timeout in such a case the transfer might
never even start before it times out.

Even in the queued up situation, the CURLOPT_CONNECTTIMEOUT_MS(3) timeout is
however treated as a per-connect timeout.

Changing this value when there are transfers in progress is possible, and the
new value is then used the next time checks are performed. Lowering the value
does however not close down any active transfers, it simply does not allow new
ones to get made.

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* do no more than 2 connections per host */
  curl_multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 2L);
}
~~~

# AVAILABILITY

Added in 7.30.0

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
