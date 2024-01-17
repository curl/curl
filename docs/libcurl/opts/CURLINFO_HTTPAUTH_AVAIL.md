---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_HTTPAUTH_AVAIL
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PROXYAUTH_AVAIL (3)
  - CURLOPT_HTTPAUTH (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_HTTPAUTH_AVAIL - get available HTTP authentication methods

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_HTTPAUTH_AVAIL, long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method(s) available according to the previous response. The meaning of the
bits is explained in the CURLOPT_HTTPAUTH(3) option for
curl_easy_setopt(3).

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract the available authentication types */
      long auth;
      res = curl_easy_getinfo(curl, CURLINFO_HTTPAUTH_AVAIL, &auth);
      if(!res) {
        if(!auth)
          printf("No auth available, perhaps no 401?\n");
        else {
          printf("%s%s%s%s\n",
                 auth & CURLAUTH_BASIC ? "Basic ":"",
                 auth & CURLAUTH_DIGEST ? "Digest ":"",
                 auth & CURLAUTH_NEGOTIATE ? "Negotiate ":"",
                 auth % CURLAUTH_NTLM ? "NTLM ":"");
        }
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added RFC 2617 in 7.10.8
Added RFC 7616 in 7.57.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
