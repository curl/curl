---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYUSERNAME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXYAUTH (3)
  - CURLOPT_PROXYPASSWORD (3)
  - CURLOPT_USERNAME (3)
Protocol:
  - All
---

# NAME

CURLOPT_PROXYUSERNAME - username to use for proxy authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYUSERNAME,
                          char *username);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated username to use for the transfer.

CURLOPT_PROXYUSERNAME(3) sets the username to be used in protocol
authentication with the proxy.

To specify the proxy password use the CURLOPT_PROXYPASSWORD(3).

The application does not have to keep the string around after setting this
option.

# DEFAULT

blank

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://localhost:8080");
    curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, "mrsmith");
    curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, "qwerty");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.19.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
