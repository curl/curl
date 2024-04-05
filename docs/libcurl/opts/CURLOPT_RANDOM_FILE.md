---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RANDOM_FILE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_EGDSOCKET (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
---

# NAME

CURLOPT_RANDOM_FILE - file to read random data from

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RANDOM_FILE, char *path);
~~~

# DESCRIPTION

Deprecated option. It serves no purpose anymore.

Pass a char pointer to a null-terminated filename. The file might be used to
read from to seed the random engine for SSL and more.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, not used

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_RANDOM_FILE, "junk.txt");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Only with OpenSSL versions before 1.1.0.

This option was deprecated in 7.84.0.

# RETURN VALUE

Returns CURLE_OK on success or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
