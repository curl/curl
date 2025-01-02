---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FILETIME
Section: 3
Source: libcurl
See-also:
  - CURLINFO_FILETIME (3)
  - curl_easy_getinfo (3)
Protocol:
  - HTTP
  - FTP
  - SFTP
  - FILE
  - SMB
Added-in: 7.5
---

# NAME

CURLOPT_FILETIME - get the modification time of the remote resource

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FILETIME, long gettime);
~~~

# DESCRIPTION

Pass a long. If it is 1, libcurl attempts to get the modification time of the
remote document in this operation. This requires that the remote server sends
the time or replies to a time querying command. The curl_easy_getinfo(3)
function with the CURLINFO_FILETIME(3) argument can be used after a
transfer to extract the received time (if any).

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/path.html");
    /* Ask for filetime */
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      long filetime;
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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
