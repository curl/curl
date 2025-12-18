---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_XFER_ID
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CONN_ID (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 8.2.0
---

# NAME

CURLINFO_XFER_ID - get the ID of a transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_XFER_ID,
                           curl_off_t *xfer_id);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the identifier of the
current/last transfer done with the handle. Stores -1 if no transfer
has been started yet for the handle.

The transfer id is unique among all transfers performed using the same
connection cache. This is implicitly the case for all transfers in the
same multi handle.

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
      curl_off_t xfer_id;
      res = curl_easy_getinfo(curl, CURLINFO_XFER_ID, &xfer_id);
      if(!res) {
        printf("Transfer ID: %" CURL_FORMAT_CURL_OFF_T "\n", xfer_id);
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
