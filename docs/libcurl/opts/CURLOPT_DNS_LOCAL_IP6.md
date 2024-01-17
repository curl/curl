---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_LOCAL_IP6
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_INTERFACE (3)
  - CURLOPT_DNS_LOCAL_IP4 (3)
  - CURLOPT_DNS_SERVERS (3)
---

# NAME

CURLOPT_DNS_LOCAL_IP6 - IPv6 address to bind DNS resolves to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DNS_LOCAL_IP6, char *address);
~~~

# DESCRIPTION

Set the local IPv6 *address* that the resolver should bind to. The argument
should be of type char * and contain a single IPv6 address as a string. Set
this option to NULL to use the default setting (do not bind to a specific IP
address).

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_DNS_LOCAL_IP6, "fe80::a9ff:fe46:b619");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

This option requires that libcurl was built with a resolver backend that
supports this operation. The c-ares backend is the only such one.

Added in 7.33.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not,
CURLE_NOT_BUILT_IN if support was disabled at compile-time, or
CURLE_BAD_FUNCTION_ARGUMENT when given a bad address.
