---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SERVER_RESPONSE_TIMEOUT_MS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECTTIMEOUT (3)
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - FTP
  - IMAP
  - POP3
  - SMTP
  - SFTP
  - SCP
Added-in: 8.6.0
---

# NAME

CURLOPT_SERVER_RESPONSE_TIMEOUT_MS - time allowed to wait for server response

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SERVER_RESPONSE_TIMEOUT_MS,
                          long timeout);
~~~

# DESCRIPTION

Pass a long. Causes libcurl to set a *timeout* period (in milliseconds) on the
amount of time that the server is allowed to take in order to send a response
message for a command before the session is considered dead. While libcurl is
waiting for a response, this value overrides CURLOPT_TIMEOUT(3). It is
recommended that if used in conjunction with CURLOPT_TIMEOUT(3), you set
CURLOPT_SERVER_RESPONSE_TIMEOUT_MS(3) to a value smaller than
CURLOPT_TIMEOUT(3).

The maximum accepted value is 2147483648.

This is the millisecond version of CURLOPT_SERVER_RESPONSE_TIMEOUT(3).

# DEFAULT

None

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/slow.txt");
    /* wait no more than 237 milliseconds */
    curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT_MS, 237L);
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
