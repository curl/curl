---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIE_CONTEXT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIE_SITE (3)
Protocol:
  - HTTP
Added-in: 8.24.0
---

# NAME

CURLOPT_COOKIE_CONTEXT - context of the request for cookie decisions

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COOKIE_CONTEXT, long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask describing the context this request is made in.
libcurl uses it together with CURLOPT_COOKIE_SITE(3) when deciding which
cookies to send and which received cookies to store. The bits have no effect
unless a site is set with CURLOPT_COOKIE_SITE(3).

Available bits in the bitmask

## CURLCOOKIE_NAVIGATION (1)

The request is a top-level navigation, like a user following a link or
submitting a form, as opposed to a request for a subresource like an image
or a script or a request made from a subframe.

Cookies with `SameSite=Lax`, or without a `SameSite` attribute, are sent on
cross-site top-level navigations when the request method is safe (GET, HEAD,
OPTIONS or TRACE). Cookies received in response to a top-level navigation
are stored even when the navigation is cross-site. `Partitioned` cookies
are keyed by, and sent for, the site navigated to.

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
    /* the user followed a link from https://example.com/ */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.net/");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIE_SITE, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_COOKIE_CONTEXT,
                     (long)CURLCOOKIE_NAVIGATION);

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
