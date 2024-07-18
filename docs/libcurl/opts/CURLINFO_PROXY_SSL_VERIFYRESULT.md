---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PROXY_SSL_VERIFYRESULT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SSL_VERIFYRESULT (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.52.0
---

# NAME

CURLINFO_PROXY_SSL_VERIFYRESULT - get the result of the proxy certificate verification

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PROXY_SSL_VERIFYRESULT,
                           long *result);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the result of the certificate verification
that was requested (using the CURLOPT_PROXY_SSL_VERIFYPEER(3)
option. This is only used for HTTPS proxies.

0 is a positive result. Non-zero is an error.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    long verifyresult;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy:443");

    res = curl_easy_perform(curl);
    if(res) {
      printf("error: %s\n", curl_easy_strerror(res));
      curl_easy_cleanup(curl);
      return 1;
    }

    res = curl_easy_getinfo(curl, CURLINFO_PROXY_SSL_VERIFYRESULT,
                            &verifyresult);
    if(!res) {
      printf("The peer verification said %s\n",
             (verifyresult ? "bad" : "fine"));
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
