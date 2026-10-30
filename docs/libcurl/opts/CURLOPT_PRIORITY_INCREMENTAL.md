---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PRIORITY_INCREMENTAL
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PIPELINING (3)
  - CURLOPT_PRIORITY_URGENCY (3)
Protocol:
  - HTTP
Added-in: 8.24.0
---

# NAME

CURLOPT_PRIORITY_INCREMENTAL - RFC 9218 priority incremental flag

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PRIORITY_INCREMENTAL,
                          long incremental);
~~~

# DESCRIPTION

Pass a long set to 1 to mark this request as *incremental* as defined by RFC
9218, the HTTP priority scheme. An incremental response is
one the client can make use of as it arrives, like a progressive image or a
streamed document. A server that supports the scheme may then share the
connection between several incremental responses of the same urgency instead
of sending them one after the other.

When the flag is set or an urgency is given with CURLOPT_PRIORITY_URGENCY(3),
libcurl adds a `Priority:` request header to requests done over HTTP/2 and
HTTP/3. The header is not sent over HTTP/1.x, where it has no effect.

This option can be changed during a transfer, from a callback or from the
application between calls to curl_multi_perform(3) or
curl_multi_socket_action(3). libcurl then sends the updated priority to the
server in a PRIORITY_UPDATE frame, over HTTP/2 when the server has announced
that it supports the scheme and always over HTTP/3. A transfer in a multi
handle is woken up to send it right away.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/photo.jpg");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    /* a progressive image can be shown while it loads */
    curl_easy_setopt(curl, CURLOPT_PRIORITY_URGENCY, 5L);
    curl_easy_setopt(curl, CURLOPT_PRIORITY_INCREMENTAL, 1L);

    result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
