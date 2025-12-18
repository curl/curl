---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_USE_PRET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FTP_USE_EPRT (3)
  - CURLOPT_FTP_USE_EPSV (3)
Protocol:
  - FTP
Added-in: 7.20.0
---

# NAME

CURLOPT_FTP_USE_PRET - use PRET for FTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_USE_PRET, long enable);
~~~

# DESCRIPTION

Pass a long. If the value is 1, it tells curl to send a PRET command before
PASV (and EPSV). Certain FTP servers, mainly drftpd, require this non-standard
command for directory listings as well as up and downloads in PASV mode. Has
no effect when using the active FTP transfers mode.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL,
                     "ftp://example.com/old-server/file.txt");

    /* a drftpd server, do it */
    curl_easy_setopt(curl, CURLOPT_FTP_USE_PRET, 1L);

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
