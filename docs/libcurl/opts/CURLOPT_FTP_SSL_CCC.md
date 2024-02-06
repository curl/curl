---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_SSL_CCC
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FTPSSLAUTH (3)
  - CURLOPT_PROTOCOLS_STR (3)
  - CURLOPT_USE_SSL (3)
---

# NAME

CURLOPT_FTP_SSL_CCC - switch off SSL again with FTP after auth

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_SSL_CCC,
                          long how);
~~~

# DESCRIPTION

If enabled, this option makes libcurl use CCC (Clear Command Channel). It
shuts down the SSL/TLS layer after authenticating. The rest of the control
channel communication remains unencrypted. This allows NAT routers to follow
the FTP transaction. Pass a long using one of the values below

## CURLFTPSSL_CCC_NONE

do not attempt to use CCC.

## CURLFTPSSL_CCC_PASSIVE

Do not initiate the shutdown, but wait for the server to do it. Do not send a
reply.

## CURLFTPSSL_CCC_ACTIVE

Initiate the shutdown and wait for a reply.

# DEFAULT

CURLFTPSSL_CCC_NONE

# PROTOCOLS

FTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/file.txt");
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_CONTROL);
    /* go back to clear-text FTP after authenticating */
    curl_easy_setopt(curl, CURLOPT_FTP_SSL_CCC, (long)CURLFTPSSL_CCC_ACTIVE);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.16.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
