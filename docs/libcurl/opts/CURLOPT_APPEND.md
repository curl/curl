---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_APPEND
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DIRLISTONLY (3)
  - CURLOPT_RESUME_FROM (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - FTP
  - SFTP
Added-in: 7.17.0
---

# NAME

CURLOPT_APPEND - append to the remote file

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_APPEND, long append);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to append to the remote file
instead of overwrite it. This is only useful when uploading to an FTP site.

# DEFAULT

0 (disabled)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {

    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/dir/to/newfile");
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_APPEND, 1L);

    curl_easy_perform(curl);
  }
}
~~~

# HISTORY

This option was known as CURLOPT_FTPAPPEND up to 7.16.4

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
