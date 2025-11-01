---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SERVER_RESPONSE_TIMEOUT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SERVER_RESPONSE_TIMEOUT_MS (3)
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
Added-in: 7.20.0
---

# NAME

CURLOPT_SERVER_RESPONSE_TIMEOUT - time allowed to wait for server response

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SERVER_RESPONSE_TIMEOUT,
                          long timeout);
~~~

# DESCRIPTION

Pass a long. It tells libcurl to wait no longer than *timeout* seconds for
responses on sent commands. If no response is received within this period, the
connection is considered dead and the transfer fails.

It is recommended that if used in conjunction with CURLOPT_TIMEOUT(3), you set
CURLOPT_SERVER_RESPONSE_TIMEOUT(3) to a value smaller than CURLOPT_TIMEOUT(3).

# DEFAULT

60 seconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/slow.txt");
    /* wait no more than 23 seconds */
    curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 23L);
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

This option was formerly known as CURLOPT_FTP_RESPONSE_TIMEOUT.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
