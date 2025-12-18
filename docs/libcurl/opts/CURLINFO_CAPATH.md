---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CAPATH
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAINFO (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - wolfSSL
Added-in: 7.84.0
---

# NAME

CURLINFO_CAPATH - get the default built-in CA path string

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CAPATH, char **path);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the default built-in path used for the CURLOPT_CAPATH(3)
option unless set by the user.

Note that in a situation where libcurl has been built to support multiple TLS
libraries, this option might return a string even if the specific TLS library
currently set to be used does not support CURLOPT_CAPATH(3).

This is a path identifying a directory.

The **path** pointer is set to NULL if there is no default path.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    char *capath = NULL;
    curl_easy_getinfo(curl, CURLINFO_CAPATH, &capath);
    if(capath) {
      printf("default ca path: %s\n", capath);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
