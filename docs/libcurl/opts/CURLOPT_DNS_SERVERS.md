---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_SERVERS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_CACHE_TIMEOUT (3)
  - CURLOPT_DNS_LOCAL_IP4 (3)
  - CURLOPT_DNS_LOCAL_IP6 (3)
---

# NAME

CURLOPT_DNS_SERVERS - DNS servers to use

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DNS_SERVERS, char *servers);
~~~

# DESCRIPTION

Pass a char pointer that is the list of DNS servers to be used instead of the
system default. The format of the dns servers option is:

host[:port][,host[:port]]...

For example:

192.168.1.100,192.168.1.101,3.4.5.6

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL - use system default

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
    curl_easy_setopt(curl, CURLOPT_DNS_SERVERS,
                     "192.168.1.100:53,192.168.1.101");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

This option requires that libcurl was built with a resolver backend that
supports this operation. The c-ares backend is the only such one.

Added in 7.24.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not,
CURLE_NOT_BUILT_IN if support was disabled at compile-time,
CURLE_BAD_FUNCTION_ARGUMENT when given an invalid server list, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
