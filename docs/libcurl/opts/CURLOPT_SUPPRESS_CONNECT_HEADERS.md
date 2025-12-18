---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SUPPRESS_CONNECT_HEADERS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADER (3)
  - CURLOPT_HTTPPROXYTUNNEL (3)
  - CURLOPT_PROXY (3)
Protocol:
  - All
Added-in: 7.54.0
---

# NAME

CURLOPT_SUPPRESS_CONNECT_HEADERS - suppress proxy CONNECT response headers

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SUPPRESS_CONNECT_HEADERS, long onoff);
~~~

# DESCRIPTION

When CURLOPT_HTTPPROXYTUNNEL(3) is used and a CONNECT request is made,
suppress proxy CONNECT response headers from the user callback functions
CURLOPT_HEADERFUNCTION(3) and CURLOPT_WRITEFUNCTION(3).

Proxy CONNECT response headers can complicate header processing since it is
essentially a separate set of headers. You can enable this option to suppress
those headers.

For example let's assume an HTTPS URL is to be retrieved via CONNECT. On
success there would normally be two sets of headers, and each header line sent
to the header function and/or the write function. The data given to the
callbacks would look like this:

~~~c
HTTP/1.1 200 Connection established
{headers}
...

HTTP/1.1 200 OK
Content-Type: application/json
{headers}
...

{body}
...
~~~

However by enabling this option the CONNECT response headers are suppressed,
so the data given to the callbacks would look like this:

~~~c
HTTP/1.1 200 OK
Content-Type: application/json
{headers}
...

{body}
...
~~~

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://foo:3128");
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L);
    curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);

    curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLE_OK or an error such as CURLE_UNKNOWN_OPTION.
