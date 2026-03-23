---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SPNEGO_NTLM_ALLOWED
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXYAUTH (3)
Protocol:
  - HTTP
Added-in: 8.14.0
---

# NAME

CURLOPT_SPNEGO_NTLM_ALLOWED - allow NTLM as a mechanism in SPNEGO

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SPNEGO_NTLM_ALLOWED,
                          long allowed);
~~~

# DESCRIPTION

Pass a long. Set to 0L to prevent NTLM from being used as a sub-mechanism
during SPNEGO (Negotiate) authentication. When SPNEGO would select NTLM, the
authentication attempt fails with **CURLE_AUTH_ERROR** before any NTLM tokens
are sent over the wire.

Set to 1L to allow NTLM within SPNEGO negotiation. This is the default
behavior.

This option only affects SPNEGO (Negotiate) authentication. It does not
affect bare NTLM authentication selected via **CURLAUTH_NTLM**.

# DEFAULT

1

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

    /* Disallow NTLM fallback within SPNEGO */
    curl_easy_setopt(curl, CURLOPT_SPNEGO_NTLM_ALLOWED, 0L);

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
