---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PASSWORD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXYAUTH (3)
  - CURLOPT_USERNAME (3)
  - CURLOPT_USERPWD (3)
Protocol:
  - All
Added-in: 7.19.1
---

# NAME

CURLOPT_PASSWORD - password to use in authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PASSWORD, char *pwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated password to use for the transfer.

The CURLOPT_PASSWORD(3) option should be used in conjunction with the
CURLOPT_USERNAME(3) option.

The application does not have to keep the string around after setting this
option.

# DEFAULT

blank

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    curl_easy_setopt(curl, CURLOPT_PASSWORD, "qwerty");

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
