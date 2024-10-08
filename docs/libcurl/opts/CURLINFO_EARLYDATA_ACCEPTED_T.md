---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_EARLYDATA_ACCEPTED_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EARLYDATA_SENT_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 8.11.0
---

# NAME

CURLINFO_EARLYDATA_ACCEPTED_T - get the number of TLS earlydata bytes
accepted by the server

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_EARLYDATA_ACCEPTED_T,
                           curl_off_t *amount);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the total amount of bytes of
TLSv1.3 earlydata that were accepted by the server. When no TLS early
data is used, this reports 0. When earlydata is sent, this
returns -1 until the TLS handshake with the server is complete.

Note that TLS earlydata is only attempted when CURLSSLOPT_EARLYDATA
is set for the transfer.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Perform the request */
    res = curl_easy_perform(curl);

    if(!res) {
      curl_off_t amount;
      res = curl_easy_getinfo(curl, CURLINFO_EARLYDATA_ACCEPTED_T, &amount);
      if(!res) {
        printf("TLS earlydata accepted: %" CURL_FORMAT_CURL_OFF_T
               " bytes\n", amount);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
