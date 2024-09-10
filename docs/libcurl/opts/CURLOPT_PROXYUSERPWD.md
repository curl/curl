---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYUSERPWD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYPASSWORD (3)
  - CURLOPT_PROXYTYPE (3)
  - CURLOPT_PROXYUSERNAME (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_PROXYUSERPWD - username and password to use for proxy authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYUSERPWD, char *userpwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be [username]:[password] to use
for the connection to the HTTP proxy. Both the name and the password are URL
decoded before used, so to include for example a colon in the username you
should encode it as %3A. (This is different to how CURLOPT_USERPWD(3) is
used - beware.)

Use CURLOPT_PROXYAUTH(3) to specify the authentication method.

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://localhost:8080");
    curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, "clark%20kent:superman");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if proxies are supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
