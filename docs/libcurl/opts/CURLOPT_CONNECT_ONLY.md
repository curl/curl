---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CONNECT_ONLY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPPROXYTUNNEL (3)
  - CURLOPT_VERBOSE (3)
  - curl_easy_recv (3)
  - curl_easy_send (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

CURLOPT_CONNECT_ONLY - stop when connected to target server

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CONNECT_ONLY, long only);
~~~

# DESCRIPTION

Pass a long. If the parameter equals 1, it tells the library to perform all
the required proxy authentication and connection setup, but no data transfer,
and then return.

The option can be used to simply test a connection to a server, but is more
useful when used with the CURLINFO_ACTIVESOCKET(3) option to
curl_easy_getinfo(3) as the library can set up the connection and then
the application can obtain the most recently used socket for special data
transfers.

Since 7.86.0, this option can be set to '2' and if WebSocket is used,
libcurl performs the request and reads all response headers before handing
over control to the application. For other protocols the behavior of '2'
is undefined.

Transfers marked connect only do not reuse any existing connections and
connections marked connect only are not allowed to get reused.

If the connect only transfer is done using the multi interface, the particular
easy handle must remain added to the multi handle for as long as the
application wants to use it. Once it has been removed with
curl_multi_remove_handle(3), curl_easy_send(3) and
curl_easy_recv(3) do not function.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    ret = curl_easy_perform(curl);
    if(ret == CURLE_OK) {
      /* only connected */
    }
  }
}
~~~

# HISTORY

WS and WSS support added in 7.86.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
