---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NEW_FILE_PERMS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NEW_DIRECTORY_PERMS (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - SFTP
  - SCP
  - FILE
---

# NAME

CURLOPT_NEW_FILE_PERMS - permissions for remotely created files

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NEW_FILE_PERMS,
                          long mode);
~~~

# DESCRIPTION

Pass a long as a parameter, containing the value of the permissions that are
set on newly created files on the remote server. The default value is *0644*.
The only protocols that can use this are *sftp://*, *scp://*, and *file://*.

# DEFAULT

0644

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://upload.example.com/file.txt");
    curl_easy_setopt(curl, CURLOPT_NEW_FILE_PERMS, 0664L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.16.4

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
