---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_TLSAUTH_USERNAME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_TLSAUTH_PASSWORD (3)
  - CURLOPT_PROXY_TLSAUTH_TYPE (3)
  - CURLOPT_TLSAUTH_PASSWORD (3)
  - CURLOPT_TLSAUTH_TYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_TLSAUTH_USERNAME - username to use for proxy TLS authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_TLSAUTH_USERNAME,
                          char *user);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
username to use for the HTTPS proxy TLS authentication method specified with
the CURLOPT_PROXY_TLSAUTH_TYPE(3) option. Requires that the
CURLOPT_PROXY_TLSAUTH_PASSWORD(3) option also be set.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_TYPE, "SRP");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_PASSWORD, "secret");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
