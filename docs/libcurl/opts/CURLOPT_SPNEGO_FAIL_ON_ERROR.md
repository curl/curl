---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SPNEGO_FAIL_ON_ERROR
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXYAUTH (3)
  - CURLOPT_SPNEGO_NTLM_ALLOWED (3)
Protocol:
  - HTTP
Added-in: 8.14.0
---

# NAME

CURLOPT_SPNEGO_FAIL_ON_ERROR - fail on SPNEGO authentication errors

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SPNEGO_FAIL_ON_ERROR,
                          long fail);
~~~

# DESCRIPTION

Pass a long. Set to 1L to make libcurl return **CURLE_AUTH_ERROR** when
SPNEGO (Negotiate) authentication fails, instead of continuing
unauthenticated.

Set to 0L to continue unauthenticated when SPNEGO fails. This is the default
behavior for backward compatibility.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NEGOTIATE);
    curl_easy_setopt(curl, CURLOPT_USERPWD, ":");

    /* Fail if SPNEGO auth cannot proceed */
    curl_easy_setopt(curl, CURLOPT_SPNEGO_FAIL_ON_ERROR, 1L);

    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
