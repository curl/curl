---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_TRANSFER_MODE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CRLF (3)
  - CURLOPT_HTTPPROXYTUNNEL (3)
  - CURLOPT_PROXY (3)
  - CURLOPT_TRANSFERTEXT (3)
Protocol:
    - All
---

# NAME

CURLOPT_PROXY_TRANSFER_MODE - append FTP transfer mode to URL for proxy

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_TRANSFER_MODE,
                          long enabled);
~~~

# DESCRIPTION

Pass a long. If the value is set to 1 (one), it tells libcurl to set the
transfer mode (binary or ASCII) for FTP transfers done via an HTTP proxy, by
appending ;type=a or ;type=i to the URL. Without this setting, or it being set
to 0 (zero, the default), CURLOPT_TRANSFERTEXT(3) has no effect when
doing FTP via a proxy. Beware that not all proxies support this feature.

# DEFAULT

0, disabled

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL,
                     "ftp://example.com/old-server/file.txt");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://localhost:80");
    curl_easy_setopt(curl, CURLOPT_PROXY_TRANSFER_MODE, 1L);
    curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.18.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if the
enabled value is not supported.
