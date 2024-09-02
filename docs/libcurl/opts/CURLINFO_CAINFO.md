---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CAINFO
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAPATH (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.84.0
---

# NAME

CURLINFO_CAINFO - get the default built-in CA certificate path

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CAINFO, char **path);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the default built-in path used for the CURLOPT_CAINFO(3)
option unless set by the user.

Note that in a situation where libcurl has been built to support multiple TLS
libraries, this option might return a string even if the specific TLS library
currently set to be used does not support CURLOPT_CAINFO(3).

This is a path identifying a single file containing CA certificates.

The **path** pointer is set to NULL if there is no default path.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    char *cainfo = NULL;
    curl_easy_getinfo(curl, CURLINFO_CAINFO, &cainfo);
    if(cainfo) {
      printf("default ca info path: %s\n", cainfo);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
