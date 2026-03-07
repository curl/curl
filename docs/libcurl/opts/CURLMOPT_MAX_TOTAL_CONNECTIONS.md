---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_MAX_TOTAL_CONNECTIONS
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_MAXCONNECTS (3)
  - CURLMOPT_MAX_HOST_CONNECTIONS (3)
Protocol:
  - All
Added-in: 7.30.0
---

# NAME

CURLMOPT_MAX_TOTAL_CONNECTIONS - max simultaneously open connections

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                            long amount);
~~~

# DESCRIPTION

Pass a long for the **amount**. The set number is used as the maximum number
of simultaneously open connections in total using this multi handle. For each
new session, libcurl might open a new connection up to the limit set by
CURLMOPT_MAX_TOTAL_CONNECTIONS(3). If CURLMOPT_PIPELINING(3) is enabled,
libcurl can try multiplexing if the host is capable of it.

When more transfers are added to the multi handle than what can be performed
due to the set limit, they get queued up waiting for their chance.

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

0, which means that there is no limit. It is then simply controlled by the
number of easy handles added concurrently and how much multiplexing is being
done.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* never do more than 15 connections */
  curl_multi_setopt(m, CURLMOPT_MAX_TOTAL_CONNECTIONS, 15L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
