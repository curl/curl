---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NEW_DIRECTORY_PERMS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FTP_CREATE_MISSING_DIRS (3)
  - CURLOPT_NEW_FILE_PERMS (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - SFTP
  - SCP
  - FILE
Added-in: 7.16.4
---

# NAME

CURLOPT_NEW_DIRECTORY_PERMS - permissions for remotely created directories

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NEW_DIRECTORY_PERMS,
                          long mode);
~~~

# DESCRIPTION

Pass a long as a parameter, containing the value of the permissions that is
set on newly created directories on the remote server. The default value is
*0755*, but any valid value can be used. The only protocols that can use
this are *sftp://*, *scp://*, and *file://*.

# DEFAULT

0755

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL,
                     "sftp://upload.example.com/newdir/file.zip");
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, 1L);
    curl_easy_setopt(curl, CURLOPT_NEW_DIRECTORY_PERMS, 0644L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
