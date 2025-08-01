---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYAUTH
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYPORT (3)
  - CURLOPT_PROXYTYPE (3)
  - CURLOPT_PROXYUSERPWD (3)
Protocol:
  - All
Added-in: 7.10.7
---

# NAME

CURLOPT_PROXYAUTH - HTTP proxy authentication methods

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYAUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libcurl which
HTTP authentication method(s) you want it to use for your proxy
authentication. If more than one bit is set, libcurl first queries the site to
see what authentication methods it supports and then it picks the best one you
allow it to use. For some methods, this induces an extra network round-trip.
Set the actual name and password with the CURLOPT_PROXYUSERPWD(3)
option.

The bitmask can be constructed by the bits listed and described in the
CURLOPT_HTTPAUTH(3) man page.

# DEFAULT

CURLAUTH_BASIC

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* use this proxy */
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://local.example.com:1080");
    /* allow whatever auth the proxy speaks */
    curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
    /* set the proxy credentials */
    curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, "james:007");
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

**CURLAUTH_*** macros became `long` types in 7.26.0, prior to this version
a `long` cast was necessary when passed to curl_easy_setopt(3).

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
