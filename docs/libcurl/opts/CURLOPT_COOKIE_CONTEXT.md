---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIE_CONTEXT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIE_SITE (3)
  - CURLOPT_FOLLOWLOCATION (3)
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

The request is a *navigation*: it loads a new page, like when a user follows a
link or submits a form. Without this bit, the request is made for a part of
the page of the site, like an image, a script or a frame.

A navigation to a hostname that is not same-site with the site set with
CURLOPT_COOKIE_SITE(3) is a *cross-site navigation*. libcurl treats it
differently from other cross-site requests. Cookies with `SameSite=Lax`, or
without a `SameSite` attribute, are sent when the request uses one of the
methods GET, HEAD, OPTIONS, TRACE or QUERY. Cookies in the response are stored
even when they do not have `SameSite=None`. `Partitioned` cookies get the
scheme and hostname of the request URL as partition key instead of the site,
since the page navigated to becomes the new site. For the requests made for
parts of that page, set CURLOPT_COOKIE_SITE(3) to that scheme and hostname to
get the cookies sent again.

# REDIRECTS

When libcurl follows a redirect with CURLOPT_FOLLOWLOCATION(3), the site and
this context remain set for every request in the chain. libcurl evaluates each
request on its own, with the hostname of the URL it goes to and the method it
actually uses. A redirect to another hostname can therefore be a cross-site
request while the first request was same-site, and a POST navigation that a
303 response turns into a GET sends the `SameSite=Lax` cookies in that GET.

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
