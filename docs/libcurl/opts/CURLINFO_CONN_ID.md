---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CONN_ID
Section: 3
Source: libcurl
See-also:
  - CURLINFO_XFER_ID (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 8.2.0
---

# NAME

CURLINFO_CONN_ID - get the ID of the last connection used by the handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CONN_ID,
                           curl_off_t *conn_id);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the connection identifier last
used by the handle. Stores -1 if there was no connection used.

The connection id is unique among all connections using the same
connection cache. This is implicitly the case for all connections in the
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
      curl_off_t conn_id;
      res = curl_easy_getinfo(curl, CURLINFO_CONN_ID, &conn_id);
      if(!res) {
        printf("Connection used: %" CURL_FORMAT_CURL_OFF_T "\n", conn_id);
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
