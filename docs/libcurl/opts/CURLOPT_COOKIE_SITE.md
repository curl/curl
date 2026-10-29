---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIE_SITE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIEJAR (3)
  - CURLOPT_COOKIE_CONTEXT (3)
Protocol:
  - HTTP
Added-in: 8.24.0
---

# NAME

CURLOPT_COOKIE_SITE - site the request is made for

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COOKIE_SITE, char *site);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string holding the *site* this request is
made for: the scheme and the domain name of the page the request belongs to,
as in `https://example.com`. The scheme must be `http` or `https` and the
string must contain nothing else, like a port number or a path. Any other
string makes this option return CURLE_BAD_FUNCTION_ARGUMENT.

The domain name is the top-most name libcurl should treat as part of the site.
libcurl uses it as given and does not shorten it: the application decides what
the site is. With the site set to `https://example.com`, a request is
*same-site* when it uses `https` and its hostname is `example.com` or ends
with `.example.com`, like a request to `https://www.example.com/`. Every other
request is *cross-site*, like a request to `http://example.com/`,
`https://example.org/` or `https://notexample.com/`. With the site set to
`https://www.example.com`, a request to `https://example.com/` is cross-site,
since `example.com` does not end with `.www.example.com`.

A request is a *navigation* when the application sets the
CURLCOOKIE_NAVIGATION bit with CURLOPT_COOKIE_CONTEXT(3). Any other request is
made for a part of a page, like an image, a script or a frame.

With a site set, libcurl uses the `SameSite` and `Partitioned` attributes of
cookies like this.

A cookie with `SameSite=Strict` is only sent in a same-site request.

A cookie with `SameSite=Lax`, or without a valid `SameSite` attribute, is sent
in a same-site request. It is also sent in a cross-site request that is a
navigation and uses one of the methods GET, HEAD, OPTIONS, TRACE or QUERY, the
methods that are not meant to change anything on the server.

A cookie with `SameSite=None` is sent in every request. It is only stored and
sent when it also has the `Secure` attribute.

A cookie in the response to a cross-site request is not stored, unless the
cookie has `SameSite=None` or the request is a navigation.

A cookie with the `Partitioned` attribute is only stored when it also has the
`Secure` attribute. libcurl stores it together with a *partition key* and only
sends it in a request with the same partition key. The partition key of a
request is the site set with this option, in lowercase. In a navigation, the
partition key is instead the scheme and hostname of the request URL, since the
page it loads becomes the new site. A `Partitioned` cookie received while no
site is set gets the scheme of the request and its own domain as partition
key.

A redirect that libcurl follows with CURLOPT_FOLLOWLOCATION(3) keeps the site
and the context set, and libcurl evaluates each request in the chain on its
own: with the hostname of the URL it goes to and with the method it actually
uses. A cross-site POST navigation that a 303 response turns into a GET sends
the `SameSite=Lax` cookies in that GET.

When no site is set, which is the default, nothing changes: libcurl stores and
sends cookies, and writes the cookie jar, exactly as versions before this
option existed. The `SameSite` and `Partitioned` attributes are then only
remembered in the cookie jar, on a `#curl:` comment line immediately before
the cookie line, once a site has been used with the cookie store or such a
line was read from a jar. CURLINFO_COOKIELIST(3) never includes the
attributes.

The application does not keep the string around after setting this option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    /* an image on a page on https://www.example.com/ */
    curl_easy_setopt(curl, CURLOPT_URL, "https://cdn.example.net/logo.png");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIE_SITE, "https://example.com");

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
