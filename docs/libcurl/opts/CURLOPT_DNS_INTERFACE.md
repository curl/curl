---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_INTERFACE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_LOCAL_IP4 (3)
  - CURLOPT_DNS_LOCAL_IP6 (3)
  - CURLOPT_DNS_SERVERS (3)
  - CURLOPT_INTERFACE (3)
Protocol:
  - All
Added-in: 7.33.0
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
    curl_easy_setopt(curl, CURLOPT_DNS_INTERFACE, "eth0");
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

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
