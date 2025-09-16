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
  - CURLOPT_FTPPORT (3)
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
server to connect back to libcurl when an active FTP connection is used. When
active FTP is used, the client (libcurl) tells the server to do a TCP connect
back to the client, instead of vice versa for passive FTP.

This option has no purpose for passive FTP.

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

    /* wait no more than 5 seconds for the FTP server to connect */
    curl_easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, 5000L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
