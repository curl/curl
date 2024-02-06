---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_RESPONSE_CODE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_HTTP_CONNECTCODE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_RESPONSE_CODE - get the last response code

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_RESPONSE_CODE, long *codep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the last received HTTP, FTP, SMTP or LDAP
(OpenLDAP only) response code. This option was previously known as
CURLINFO_HTTP_CODE in libcurl 7.10.7 and earlier. The stored value is zero if
no server response code has been received.

Note that a proxy's CONNECT response should be read with
CURLINFO_HTTP_CONNECTCODE(3) and not this.

# PROTOCOLS

HTTP, FTP, SMTP and LDAP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.10.8. CURLINFO_HTTP_CODE was added in 7.4.1.
Support for SMTP responses added in 7.25.0, for OpenLDAP in 7.81.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
