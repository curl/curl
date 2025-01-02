---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_KEYDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_KEYDATA (3)
  - CURLOPT_SSH_KNOWNHOSTS (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.19.6
---

# NAME

CURLOPT_SSH_KEYDATA - pointer passed to the SSH key callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_KEYDATA, void *pointer);
~~~

# DESCRIPTION

Pass a void * as parameter. This *pointer* is passed along verbatim to the
callback set with CURLOPT_SSH_KEYFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};
static int keycb(CURL *easy,
                 const struct curl_khkey *knownkey,
                 const struct curl_khkey *foundkey,
                 enum curl_khmatch match,
                 void *clientp)
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return CURLKHSTAT_FINE_ADD_TO_FILE;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct mine callback_data;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/thisfile.txt");
    curl_easy_setopt(curl, CURLOPT_SSH_KEYFUNCTION, keycb);
    curl_easy_setopt(curl, CURLOPT_SSH_KEYDATA, &callback_data);
    curl_easy_setopt(curl, CURLOPT_SSH_KNOWNHOSTS, "/home/user/known_hosts");

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
