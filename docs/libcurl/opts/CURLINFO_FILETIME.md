---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_FILETIME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FILETIME (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_FILETIME - get the remote time of the retrieved document

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_FILETIME, long *timep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the remote time of the retrieved document
in number of seconds since January 1 1970 in the GMT/UTC time zone. If you get
-1, it can be because of many reasons (it might be unknown, the server might
hide it or the server does not support the command that tells document time
etc) and the time of the document is unknown.

You must tell libcurl to collect this information before the transfer is made,
by using the CURLOPT_FILETIME(3) option to curl_easy_setopt(3) or
you this unconditionally gets a -1 back.

Consider using CURLINFO_FILETIME_T(3) to be able to extract dates beyond
the year 2038 on systems using 32 bit longs (Windows).

# PROTOCOLS

HTTP(S), FTP(S), SFTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    /* Ask for filetime */
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      long filetime = 0;
      res = curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
      if((CURLE_OK == res) && (filetime >= 0)) {
        time_t file_time = (time_t)filetime;
        printf("filetime: %s", ctime(&file_time));
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.5

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
