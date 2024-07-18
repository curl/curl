---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYHEADER
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADEROPT (3)
  - CURLOPT_HTTPHEADER (3)
Protocol:
  - All
Added-in: 7.37.0
---

# NAME

CURLOPT_PROXYHEADER - set of HTTP headers to pass to proxy

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYHEADER,
                          struct curl_slist *headers);
~~~

# DESCRIPTION

Pass a pointer to a linked list of HTTP headers to pass in your HTTP request
sent to a proxy. The rules for this list is identical to the
CURLOPT_HTTPHEADER(3) option's.

The headers set with this option is only ever used in requests sent to a proxy
- when there is also a request sent to a host.

The first line in a request (containing the method, usually a GET or POST) is
NOT a header and cannot be replaced using this option. Only the lines
following the request-line are headers. Adding this method line in this list
of headers causes your request to send an invalid header.

Pass a NULL to this to reset back to no custom headers.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();

  struct curl_slist *list;

  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://proxy.example.com:80");

    list = curl_slist_append(NULL, "Shoesize: 10");
    list = curl_slist_append(list, "Accept:");

    curl_easy_setopt(curl, CURLOPT_PROXYHEADER, list);

    curl_easy_perform(curl);

    curl_slist_free_all(list); /* free the list again */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
