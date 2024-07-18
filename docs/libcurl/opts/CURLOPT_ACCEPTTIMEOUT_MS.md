---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ACCEPTTIMEOUT_MS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECTTIMEOUT_MS (3)
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_STDERR (3)
Protocol:
  - FTP
Added-in: 7.24.0
---

# NAME

CURLOPT_ACCEPTTIMEOUT_MS - timeout waiting for FTP server to connect back

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ACCEPTTIMEOUT_MS, long ms);
~~~

# DESCRIPTION

Pass a long telling libcurl the maximum number of milliseconds to wait for a
server to connect back to libcurl when an active FTP connection is used.

# DEFAULT

60000 milliseconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/path/file");

    /* wait no more than 5 seconds for FTP server responses */
    curl_easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, 5000L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
