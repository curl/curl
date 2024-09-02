---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_HOST_PUBLIC_KEY_MD5
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_AUTH_TYPES (3)
  - CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 (3)
  - CURLOPT_SSH_KNOWNHOSTS (3)
  - CURLOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.17.1
---

# NAME

CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 - MD5 checksum of SSH server public key

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                          char *md5);
~~~

# DESCRIPTION

Pass a char pointer pointing to a string containing 32 hexadecimal digits. The
string should be the 128 bit MD5 checksum of the remote host's public key, and
libcurl aborts the connection to the host unless the MD5 checksum match.

MD5 is a weak algorithm. We strongly recommend using
CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256(3) instead.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/file");
    curl_easy_setopt(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                     "afe17cd62a0f3b61f1ab9cb22ba269a7");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
