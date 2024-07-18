---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_HOSTKEYDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_HOSTKEYFUNCTION (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.84.0
---

# NAME

CURLOPT_SSH_HOSTKEYDATA - pointer to pass to the SSH host key callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_HOSTKEYDATA, void *pointer);
~~~

# DESCRIPTION

Pass a void * as parameter. This *pointer* is passed along untouched to
the callback set with CURLOPT_SSH_HOSTKEYFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};

static int hostkeycb(void *clientp,   /* CURLOPT_SSH_HOSTKEYDATA */
                     int keytype,     /* CURLKHTYPE */
                     const char *key, /* host key to check */
                     size_t keylen)   /* length of the key */
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return CURLKHMATCH_OK;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct mine callback_data;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/thisfile.txt");
    curl_easy_setopt(curl, CURLOPT_SSH_HOSTKEYFUNCTION, hostkeycb);
    curl_easy_setopt(curl, CURLOPT_SSH_HOSTKEYDATA, &callback_data);

    curl_easy_perform(curl);
  }
}
~~~

# NOTES

Works only with the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
