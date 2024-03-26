---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FORBID_REUSE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_MAXCONNECTS (3)
  - CURLOPT_MAXLIFETIME_CONN (3)
Protocol:
  - All
---

# NAME

CURLOPT_FORBID_REUSE - make connection get closed at once after use

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FORBID_REUSE, long close);
~~~

# DESCRIPTION

Pass a long. Set *close* to 1 to make libcurl explicitly close the
connection when done with the transfer. Normally, libcurl keeps all
connections alive when done with one transfer in case a succeeding one follows
that can reuse them. This option should be used with caution and only if you
understand what it does as it can seriously impact performance.

Set to 0 to have libcurl keep the connection open for possible later reuse
(default behavior).

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_perform(curl);

    /* this second transfer may not reuse the same connection */
    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
