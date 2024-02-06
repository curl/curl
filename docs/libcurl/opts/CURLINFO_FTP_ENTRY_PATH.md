---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_FTP_ENTRY_PATH
Section: 3
Source: libcurl
See-also:
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_FTP_ENTRY_PATH - get entry path in FTP server

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_FTP_ENTRY_PATH, char **path);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive a pointer to a string holding the
path of the entry path. That is the initial path libcurl ended up in when
logging on to the remote FTP server. This stores a NULL as pointer if
something is wrong.

The **path** pointer is NULL or points to private memory. You MUST NOT free
- it gets freed when you call curl_easy_cleanup(3) on the corresponding
CURL handle.

# PROTOCOLS

FTP(S) and SFTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract the entry path */
      char *ep = NULL;
      res = curl_easy_getinfo(curl, CURLINFO_FTP_ENTRY_PATH, &ep);
      if(!res && ep) {
        printf("Entry path was: %s\n", ep);
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.15.4. Works for SFTP since 7.21.4

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
