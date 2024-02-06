---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIESESSION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIE (3)
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIEJAR (3)
---

# NAME

CURLOPT_COOKIESESSION - start a new cookie session

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COOKIESESSION, long init);
~~~

# DESCRIPTION

Pass a long set to 1 to mark this as a new cookie "session". It forces libcurl
to ignore all cookies it is about to load that are "session cookies" from the
previous session. By default, libcurl always loads all cookies, independent if
they are session cookies or not. Session cookies are cookies without expiry
date and they are meant to be alive and existing for this "session" only.

A "session" is usually defined in browser land for as long as you have your
browser up, more or less. libcurl needs the application to use this option to
tell it when a new session starts, otherwise it assumes everything is still in
the same session.

# DEFAULT

0

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* new "session", do not load session cookies */
    curl_easy_setopt(curl, CURLOPT_COOKIESESSION, 1L);

    /* get the (non session) cookies from this file */
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "/tmp/cookies.txt");

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK
