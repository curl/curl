---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HAPROXY_CLIENT_IP
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_HAPROXYPROTOCOL (3)
  - CURLOPT_PROXY (3)
---

# NAME

CURLOPT_HAPROXY_CLIENT_IP - set HAProxy PROXY protocol client IP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HAPROXY_CLIENT_IP,
                          char *client_ip);
~~~

# DESCRIPTION

When this parameter is set to a valid IPv4 or IPv6 numerical address, the
library sends this address as client address in the HAProxy PROXY protocol v1
header at beginning of the connection.

This option is an alternative to CURLOPT_HAPROXYPROTOCOL(3) as that one
cannot use a specified address.

# DEFAULT

NULL, no HAProxy header is sent

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, "1.1.1.1");
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP. Added in 8.2.0.

# RETURN VALUE

Returns CURLE_OK if HTTP is enabled, and CURLE_UNKNOWN_OPTION if not.
