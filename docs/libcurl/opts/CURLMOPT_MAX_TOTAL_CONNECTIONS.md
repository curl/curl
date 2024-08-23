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
CURLMOPT_MAX_TOTAL_CONNECTIONS(3). When the limit is reached, new
sessions are held pending until there are available connections. If
CURLMOPT_PIPELINING(3) is enabled, libcurl can try multiplexing if the
host is capable of it.

When more transfers are added to the multi handle than what can be performed
due to the set limit, they get queued up waiting for their chance. When that
happens, the CURLOPT_TIMEOUT_MS(3) timeout is counted inclusive of the
waiting time, meaning that if you set a too narrow timeout in such a case the
transfer might never even start before it times out.

Even in the queued up situation, the CURLOPT_CONNECTTIMEOUT_MS(3)
timeout is however treated as a per-connect timeout.

# DEFAULT

0, which means that there is no limit. It is then simply controlled by the
number of easy handles added.

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

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
