---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_POSTREDIR
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EFFECTIVE_METHOD (3)
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - CURLOPT_MAXREDIRS (3)
  - CURLOPT_POSTFIELDS (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_POSTREDIR - how to act on an HTTP POST redirect

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_POSTREDIR,
                          long bitmask);
~~~

# DESCRIPTION

Pass a bitmask to control how libcurl acts on redirects after POSTs that get a
301, 302 or 303 response back. A parameter with bit 0 set (value
**CURL_REDIR_POST_301**) tells the library to respect RFC 7231 (section
6.4.2 to 6.4.4) and not convert POST requests into GET requests when following
a 301 redirection. Setting bit 1 (value **CURL_REDIR_POST_302**) makes
libcurl maintain the request method after a 302 redirect whilst setting bit 2
(value **CURL_REDIR_POST_303**) makes libcurl maintain the request method
after a 303 redirect. The value **CURL_REDIR_POST_ALL** is a convenience
define that sets all three bits.

The non-RFC behavior is ubiquitous in web browsers, so the library does the
conversion by default to maintain consistency. However, a server may require a
POST to remain a POST after such a redirection. This option is meaningful only
when setting CURLOPT_FOLLOWLOCATION(3).

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* a silly POST example */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "data=true");

    /* example.com is redirected, so we tell libcurl to send POST on 301,
       302 and 303 HTTP response codes */
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.17.1. This option was known as CURLOPT_POST301 up to 7.19.0 as it
only supported the 301 then. CURL_REDIR_POST_303 was added in 7.26.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
