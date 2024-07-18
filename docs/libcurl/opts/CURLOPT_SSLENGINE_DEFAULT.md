---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSLENGINE_DEFAULT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSLCERT (3)
  - CURLOPT_SSLENGINE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.9.3
---

# NAME

CURLOPT_SSLENGINE_DEFAULT - make SSL engine default

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSLENGINE_DEFAULT, long val);
~~~

# DESCRIPTION

Pass a long set to 1 to make the already specified crypto engine the default
for (asymmetric) crypto operations.

This option has no effect unless set after CURLOPT_SSLENGINE(3).

# DEFAULT

None

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSLENGINE, "dynamic");
    curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLE_OK - Engine set as default.

CURLE_SSL_ENGINE_SETFAILED - Engine could not be set as default.

CURLE_NOT_BUILT_IN - Option not built in, OpenSSL is not the SSL backend.

CURLE_UNKNOWN_OPTION - Option not recognized.

CURLE_OUT_OF_MEMORY - Insufficient heap space.
