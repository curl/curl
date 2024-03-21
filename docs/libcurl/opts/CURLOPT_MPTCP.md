---
c: Copyright (C) Dorian Craps, <dorian.craps@student.vinci.be>
SPDX-License-Identifier: curl
Title: CURLOPT_MPTCP
Section: 3
Source: libcurl
See-also:
  - tcp-fastopen (3)
---

# NAME

CURLOPT_MPTCP - enable Multipath TCP

# SYNOPSIS

~~~c

#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MPTCP, long enable);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0 to disable.

Multipath TCP (MPTCP) is an extension of TCP that allows multiple paths 
to be used simultaneously by a single TCP connection, enhancing redundancy, 
bandwidth, and potentially reducing latency. 
It works by presenting a standard TCP interface to applications while 
managing multiple underlying TCP connections.

Enabling MPTCP can improve the performance and reliability of network requests, 
particularly in environments where multiple network paths (e.g., WiFi and 
cellular) are available.

Note: MPTCP support depends on the underlying operating system and network 
infrastructure. Not all networks support MPTCP, and its effectiveness will 
vary based on the network configuration and conditions.

# DEFAULT

0

# PROTOCOLS

All

# EXAMPLE

~~~c

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_MPTCP, 1L);
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Support for MPTCP in libcurl requires Linux 5.6 or later. 
The feature's availability in libcurl can also depend 
on the version of libcurl. Added in 8.7.0.

# RETURN VALUE

Returns CURLE_OK if MPTCP is successfully enabled for the connection,
 otherwise returns an error code specific to the reason it could not be enabled, 
 which might include lack of operating system support or libcurl not being built 
 with MPTCP support.