---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PRIORITY_URGENCY
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PIPELINING (3)
  - CURLOPT_PRIORITY_INCREMENTAL (3)
  - CURLOPT_STREAM_WEIGHT (3)
Protocol:
  - HTTP
Added-in: 8.24.0
---

# NAME

CURLOPT_PRIORITY_URGENCY - RFC 9218 priority urgency of the request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PRIORITY_URGENCY,
                          long urgency);
~~~

# DESCRIPTION

Pass a long with the *urgency* of this request, a number from 0 to 7 as
defined by RFC 9218, the HTTP priority scheme. 0 is the
highest urgency and 7 the lowest. A server that supports the scheme uses the
urgency to decide which responses to send first when several are in progress
over the same connection, so a browser can for example ask for style sheets
and scripts before images to make the page render sooner.

Pass -1 to not signal any urgency, which servers treat as the default urgency
3.

When an urgency is set or CURLOPT_PRIORITY_INCREMENTAL(3) is enabled,
libcurl adds a `Priority:` request header to requests done over HTTP/2 and
HTTP/3, holding the priority field value like `u=1, i`. The header is not
sent over HTTP/1.x, where it has no effect.

This option can be changed during a transfer, from a callback or from the
application between calls to curl_multi_perform(3) or
curl_multi_socket_action(3). libcurl then sends the updated priority to the
server in a PRIORITY_UPDATE frame, over HTTP/2 when the server has announced
that it supports the scheme and always over HTTP/3. A transfer in a multi
handle is woken up to send it right away.

The older CURLOPT_STREAM_WEIGHT(3) option uses the priority tree of RFC
7540, which RFC 9113 removed from HTTP/2 and most servers ignore. New
applications should use this option.

# DEFAULT

-1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/style.css");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    /* a style sheet blocks rendering, ask for it urgently */
    curl_easy_setopt(curl, CURLOPT_PRIORITY_URGENCY, 1L);

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
