---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PROXYAUTH_AVAIL
Section: 3
Source: libcurl
See-also:
  - CURLINFO_HTTPAUTH_AVAIL (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.10.8
---

# NAME

CURLINFO_PROXYAUTH_AVAIL - get available HTTP proxy authentication methods

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PROXYAUTH_AVAIL,
                           long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method(s) available according to the previous response. The meaning of the
bits is explained in the CURLOPT_PROXYAUTH(3) option for curl_easy_setopt(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:80");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract the available proxy authentication types */
      long auth;
      res = curl_easy_getinfo(curl, CURLINFO_PROXYAUTH_AVAIL, &auth);
      if(!res) {
        if(!auth)
          printf("No proxy auth available, perhaps no 407?\n");
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

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
