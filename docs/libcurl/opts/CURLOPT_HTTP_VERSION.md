---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP_VERSION
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_ALTSVC (3)
  - CURLOPT_HTTP09_ALLOWED (3)
  - CURLOPT_HTTP200ALIASES (3)
  - CURLOPT_SSLVERSION (3)
---

# NAME

CURLOPT_HTTP_VERSION - HTTP protocol version to use

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP_VERSION, long version);
~~~

# DESCRIPTION

Pass *version* a long, set to one of the values described below. They ask
libcurl to use the specific HTTP versions.

Note that the HTTP version is just a request. libcurl still prioritizes to
reuse existing connections so it might then reuse a connection using an HTTP
version you have not asked for.

## CURL_HTTP_VERSION_NONE

We do not care about what version the library uses. libcurl uses whatever it
thinks fit.

## CURL_HTTP_VERSION_1_0

Enforce HTTP 1.0 requests.

## CURL_HTTP_VERSION_1_1

Enforce HTTP 1.1 requests.

## CURL_HTTP_VERSION_2_0

Attempt HTTP 2 requests. libcurl falls back to HTTP 1.1 if HTTP 2 cannot be
negotiated with the server. (Added in 7.33.0)

When libcurl uses HTTP/2 over HTTPS, it does not itself insist on TLS 1.2 or
higher even though that is required by the specification. A user can add this
version requirement with CURLOPT_SSLVERSION(3).

The alias *CURL_HTTP_VERSION_2* was added in 7.43.0 to better reflect the
actual protocol name.

## CURL_HTTP_VERSION_2TLS

Attempt HTTP 2 over TLS (HTTPS) only. libcurl falls back to HTTP 1.1 if HTTP 2
cannot be negotiated with the HTTPS server. For clear text HTTP servers,
libcurl uses 1.1. (Added in 7.47.0)

## CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE

Issue non-TLS HTTP requests using HTTP/2 without HTTP/1.1 Upgrade. It requires
prior knowledge that the server supports HTTP/2 straight away. HTTPS requests
still do HTTP/2 the standard way with negotiated protocol version in the TLS
handshake. (Added in 7.49.0)

## CURL_HTTP_VERSION_3

(Added in 7.66.0) This option makes libcurl attempt to use HTTP/3 to the host
given in the URL, with fallback to earlier HTTP versions if needed.

## CURL_HTTP_VERSION_3ONLY

(Added in 7.88.0) Setting this makes libcurl attempt to use HTTP/3 directly to
server given in the URL and does not downgrade to earlier HTTP version if the
server does not support HTTP/3.

# DEFAULT

Since curl 7.62.0: CURL_HTTP_VERSION_2TLS

Before that: CURL_HTTP_VERSION_1_1

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                     (long)CURL_HTTP_VERSION_2TLS);
    ret = curl_easy_perform(curl);
    if(ret == CURLE_HTTP_RETURNED_ERROR) {
      /* an HTTP response error problem */
    }
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
