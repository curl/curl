---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_EARLYDATA_SENT_T
Section: 3
Source: libcurl
See-also:
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
Added-in: 8.11.0
---

# NAME

CURLINFO_EARLYDATA_SENT_T - get the number of bytes sent as TLS early data

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_EARLYDATA_SENT_T,
                           curl_off_t *amount);
~~~

# DESCRIPTION

Pass a pointer to an *curl_off_t* to receive the total amount of bytes that
were sent to the server as TLSv1.3 early data. When no TLS early
data is used, this reports 0.

TLS early data is only attempted when CURLSSLOPT_EARLYDATA is set for the
transfer. In addition, it is only used by libcurl when a TLS session exists
that announces support.

The amount is **negative** when the sent data was rejected
by the server. TLS allows a server that announces support for early data to
reject any attempt to use it at its own discretion. When for example 127
bytes had been sent, but were rejected, it reports -127 as the amount "sent".

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
      res = curl_easy_getinfo(curl, CURLINFO_EARLYDATA_SENT_T, &amount);
      if(!res) {
        printf("TLS earlydata: %" CURL_FORMAT_CURL_OFF_T " bytes\n", amount);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
