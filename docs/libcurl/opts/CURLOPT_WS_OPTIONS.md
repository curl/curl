---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_WS_OPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECT_ONLY (3)
  - curl_ws_recv (3)
  - curl_ws_send (3)
Protocol:
  - WS
Added-in: 7.86.0
---

# NAME

CURLOPT_WS_OPTIONS - WebSocket behavior options

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_WS_OPTIONS, long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask to tell libcurl about specific WebSocket
behaviors.

To detach a WebSocket connection and use the curl_ws_send(3) and
curl_ws_recv(3) functions after the HTTP upgrade procedure, set the
CURLOPT_CONNECT_ONLY(3) option to 2L.

Available bits in the bitmask

## CURLWS_RAW_MODE (1)

Deliver "raw" WebSocket traffic to the CURLOPT_WRITEFUNCTION(3)
callback.

In raw mode, libcurl does not handle pings or any other frame for the
application.

## CURLWS_NOAUTOPONG (2)

Disable the automatic reply to PING messages. This means users must
send a PONG message with curl_ws_send(3). This feature is added with
version 8.14.0.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ws://example.com/");
    /* tell curl we deal with all the WebSocket magic ourselves */
    curl_easy_setopt(curl, CURLOPT_WS_OPTIONS, (long)CURLWS_RAW_MODE);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
