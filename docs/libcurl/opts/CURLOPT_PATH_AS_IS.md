---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PATH_AS_IS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_STDERR (3)
  - CURLOPT_URL (3)
  - curl_url_set (3)
Protocol:
  - All
Added-in: 7.42.0
---

# NAME

CURLOPT_PATH_AS_IS - do not handle dot-dot sequences

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PATH_AS_IS, long leaveit);
~~~

# DESCRIPTION

Set the long *leaveit* to 1, to explicitly tell libcurl to not alter the
given path before passing it on to the server.

This instructs libcurl to NOT squash sequences of "/../" or "/./" that may
exist in the URL's path part and that is supposed to be removed according to
RFC 3986 section 5.2.4.

Some server implementations are known to (erroneously) require the dot-dot
sequences to remain in the path and some clients want to pass these on in
order to try out server implementations.

By default libcurl normalizes such sequences before using the path.

The corresponding flag for the curl_url_set(3) function is called
**CURLU_PATH_AS_IS**.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://example.com/../../etc/password");

    curl_easy_setopt(curl, CURLOPT_PATH_AS_IS, 1L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
