---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP_PRIO
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPHEADER (3)
  - CURLOPT_HTTP_VERSION (3)
  - CURLOPT_STREAM_WEIGHT (3)
  - RFC 9218
Protocol:
  - HTTP
Added-in: 8.21.0
---

# NAME

CURLOPT_HTTP_PRIO - signal request priority

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP_PRIO,
                          long priority);
~~~

# DESCRIPTION

Pass *priority* a long, set to the values described below.

Signals priority according to RFC 9218 to the server in a `Priority:`
request header field. There are two parameters defined: `urgency`
and `incremental`. These are set via the values below.

A `Priority:` header set via CURLOPT_HTTPHEADER(3) takes precedence
over this option. If and how a peer (server and/or intermediate) may
honor these signals is at the discretion of the peer.

This option can be set during transfer. Multiplexing protocols like
HTTP/2 and HTTP/3 can inform the peer about changes while the
response is being processed.

## CURL_HTTP_PRIO_NONE

There is no special priority for this request. This is equivalent
to an urgency of 3 and no incremental processing.

## CURL_HTTP_PRIO_U0

Signal that a request is of the highest urgency.

## CURL_HTTP_PRIO_U1

Signal that a request is urgent.

## CURL_HTTP_PRIO_U2

Signal that a request is somewhat urgent.

## CURL_HTTP_PRIO_U3

Signal that a request has no special urgency.

## CURL_HTTP_PRIO_U4, CURL_HTTP_PRIO_U5, CURL_HTTP_PRIO_U6, CURL_HTTP_PRIO_U7

Signal that a request is of lower urgency.

##  CURL_HTTP_PRIO_I

Signal that a response is processed incrementally, e.g. the client has
use for the response before it is complete. This value can be combined
with all urgency values.

# DEFAULT

CURL_HTTP_PRIO_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/one");

    /* signal highest urgency for request, incremental processing */
    curl_easy_setopt(curl, CURLOPT_HTTP_PRIO,
                     CURL_HTTP_PRIO_U0 | CURL_HTTP_PRIO_I);

    /* then add both to a multi handle and transfer them */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
