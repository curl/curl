---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_USE_EPRT
Section: 3
Source: libcurl
Protocol:
  - FTP
See-also:
  - CURLOPT_FTPPORT (3)
  - CURLOPT_FTP_USE_EPSV (3)
---

# NAME

CURLOPT_FTP_USE_EPRT - use EPRT for FTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_USE_EPRT, long enabled);
~~~

# DESCRIPTION

Pass a long. If the value is 1, it tells curl to use the EPRT command when
doing active FTP downloads (which is enabled by
CURLOPT_FTPPORT(3)). Using EPRT means that libcurl first attempts to use
EPRT before using PORT, but if you pass zero to this option, it avoids using
EPRT, only plain PORT.

The EPRT command is a slightly newer addition to the FTP protocol than PORT
and is the preferred command to use since it enables IPv6 to be used. Old FTP
servers might not support it, which is why libcurl has a fallback mechanism.
Sometimes that fallback is not enough and then this option might come handy.

If the server is an IPv6 host, this option has no effect as EPRT is necessary
then.

# DEFAULT

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/file.txt");

    /* contact us back, aka "active" FTP */
    curl_easy_setopt(curl, CURLOPT_FTPPORT, "-");

    /* FTP the way the neanderthals did it */
    curl_easy_setopt(curl, CURLOPT_FTP_USE_EPRT, 0L);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.10.5

# RETURN VALUE

Returns CURLE_OK
