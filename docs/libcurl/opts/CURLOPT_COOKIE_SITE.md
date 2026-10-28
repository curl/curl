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
made for. In browser terms this is the "site for cookies": the registrable
domain of the top-level document the request belongs to, such as
`example.com` for a page on `https://www.example.com/`. The string may be
prefixed with a scheme and `://`, as in `https://example.com`, in which case
the scheme of the request must match as well for the request to count as
same-site (schemeful same-site). A port or path in the string is ignored, as
in `https://example.com:8443/`. When libcurl is built with libpsl, both the
site and the request host are reduced to their registrable domains for the
check, so `www.example.com` given as site matches the host `example.com`.

When a site is set, libcurl evaluates the `SameSite` and `Partitioned`
attributes of cookies as described in RFC 6265bis and the CHIPS proposal:

A request is *same-site* when its hostname equals the site or is a subdomain
of it. Cookies with `SameSite=Strict` are only sent on same-site requests.
Cookies with `SameSite=Lax`, or without a valid `SameSite` attribute, are sent
on same-site requests and on cross-site top-level navigations using a safe
method (GET, HEAD, OPTIONS or TRACE). See CURLOPT_COOKIE_CONTEXT(3) for how
to mark a request as a top-level navigation. Cookies with `SameSite=None` are
sent on all requests.

Cookies received in a cross-site response that are not `SameSite=None` are
not stored, unless the request was a top-level navigation.

A cookie with the `Partitioned` attribute is stored together with the
top-level site it was received under, its *partition key*. It is only sent
again in requests made for the same site. Such a cookie set under one site
does not exist for another site, so an application does not need to keep
one cookie store per site to isolate them. On a top-level navigation the
top-level site is the site navigated to, the registrable domain of the
request host, not the site given here. The key is the canonical form of a
site: the scheme when one was given, and the host in lowercase without port,
path or trailing dot. A `Partitioned` cookie received while no site is set
gets its own domain as key, so it is only sent in requests made for that
site.

The string must not contain whitespace, control characters or semicolons,
since it is written to the cookie jar file. Such a string makes this option
return CURLE_BAD_FUNCTION_ARGUMENT.

When no site is set, which is the default, nothing changes: libcurl stores
and sends cookies, and writes the cookie jar, exactly as versions before this
option existed. The `SameSite` and `Partitioned` attributes are only
remembered in the cookie jar, on a `#curl:` comment line before the cookie,
once a site has been used with the cookie store or such a line was read
from a jar. CURLINFO_COOKIELIST(3) never includes the attributes.

A request redirected to another method, like a POST answered with a 303,
evaluates the cookies for the redirected request with the method actually
used, so a cross-site navigation that turns into a GET gets the `Lax`
cookies.

With a site set, libcurl does not store cookies that have `SameSite=None`
or `Partitioned` without the `Secure` attribute, and does not send such
cookies when they were stored earlier without a site.

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
    /* a subresource of a page on https://www.example.com/ */
    curl_easy_setopt(curl, CURLOPT_URL, "https://cdn.example.net/style.css");
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
