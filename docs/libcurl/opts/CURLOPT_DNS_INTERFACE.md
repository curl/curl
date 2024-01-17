---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_INTERFACE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_LOCAL_IP4 (3)
  - CURLOPT_DNS_LOCAL_IP6 (3)
  - CURLOPT_DNS_SERVERS (3)
  - CURLOPT_INTERFACE (3)
---

# NAME

CURLOPT_DNS_INTERFACE - interface to speak DNS over

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DNS_INTERFACE, char *ifname);
~~~

# DESCRIPTION

Pass a char pointer as parameter. Set the name of the network interface that
the DNS resolver should bind to. This must be an interface name (not an
address). Set this option to NULL to use the default setting (do not bind to a
specific interface).

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

All protocols except file:// - protocols that resolve host names.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_DNS_INTERFACE, "eth0");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.33.0. This option also requires that libcurl was built with a
resolver backend that supports this operation. The c-ares backend is the only
such one.

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not,
or CURLE_NOT_BUILT_IN if support was disabled at compile-time.
