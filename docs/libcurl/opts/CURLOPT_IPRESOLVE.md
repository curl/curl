---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_IPRESOLVE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTP_VERSION (3)
  - CURLOPT_RESOLVE (3)
  - CURLOPT_SSLVERSION (3)
---

# NAME

CURLOPT_IPRESOLVE - IP protocol version to use

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_IPRESOLVE, long resolve);
~~~

# DESCRIPTION

Allows an application to select what kind of IP addresses to use when
establishing a connection or choosing one from the connection pool. This is
interesting when using host names that resolve to more than one IP family.

If the URL provided for a transfer contains a numerical IP version as a host
name, this option does not override or prohibit libcurl from using that IP
version.

Available values for this option are:

## CURL_IPRESOLVE_WHATEVER

Default, can use addresses of all IP versions that your system allows.

## CURL_IPRESOLVE_V4

Uses only IPv4 addresses.

## CURL_IPRESOLVE_V6

Uses only IPv6 addresses.

# DEFAULT

CURL_IPRESOLVE_WHATEVER

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

    /* of all addresses example.com resolves to, only IPv6 ones are used */
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
