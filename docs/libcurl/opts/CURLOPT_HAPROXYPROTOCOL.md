---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HAPROXYPROTOCOL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
Protocol:
  - All
Added-in: 7.60.0
---

# NAME

CURLOPT_HAPROXYPROTOCOL - send HAProxy PROXY protocol v1 header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HAPROXYPROTOCOL,
                          long haproxy_protocol);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to send an HAProxy PROXY
protocol v1 header at beginning of the connection. The default action is not to
send this header.

This option is primarily useful when sending test requests to a service that
expects this header.

Most applications do not need this option.

# DEFAULT

0, do not send any HAProxy PROXY protocol header

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HAPROXYPROTOCOL, 1L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if HTTP is enabled, and CURLE_UNKNOWN_OPTION if not.
