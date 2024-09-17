---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_LOCAL_IP4
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_INTERFACE (3)
  - CURLOPT_DNS_LOCAL_IP6 (3)
  - CURLOPT_DNS_SERVERS (3)
Protocol:
  - All
Added-in: 7.33.0
---

# NAME

CURLOPT_DNS_LOCAL_IP4 - IPv4 address to bind DNS resolves to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DNS_LOCAL_IP4, char *address);
~~~

# DESCRIPTION

Set the local IPv4 *address* that the resolver should bind to. The argument
should be of type char * and contain a single numerical IPv4 address as a
string. Set this option to NULL to use the default setting (do not bind to a
specific IP address).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_DNS_LOCAL_IP4, "192.168.0.14");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# NOTES

This option requires that libcurl was built with a resolver backend that
supports this operation. The c-ares backend is the only such one.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not,
CURLE_NOT_BUILT_IN if support was disabled at compile-time, or
CURLE_BAD_FUNCTION_ARGUMENT when given a bad address.
