---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_ALTERNATIVE_TO_USER
Section: 3
Source: libcurl
Protocol:
  - FTP
See-also:
  - CURLOPT_FTP_ACCOUNT (3)
  - CURLOPT_FTP_SKIP_PASV_IP (3)
  - CURLOPT_SERVER_RESPONSE_TIMEOUT (3)
  - CURLOPT_USERNAME (3)
Added-in: 7.15.5
---

# NAME

CURLOPT_FTP_ALTERNATIVE_TO_USER - command to use instead of USER with FTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_ALTERNATIVE_TO_USER,
                          char *cmd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, pointing to a string which is used to
authenticate if the usual FTP "USER user" and "PASS password" negotiation
fails. This is currently only known to be required when connecting to
Tumbleweed's Secure Transport FTPS server using client certificates for
authentication.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER, "two users");
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
