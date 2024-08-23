---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_AUTH_TYPES (3)
  - CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
  - CURLOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.80.0
---

# NAME

CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 - SHA256 hash of SSH server public key

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                          char *sha256);
~~~

# DESCRIPTION

Pass a char pointer pointing to a string containing a Base64-encoded SHA256
hash of the remote host's public key. The transfer fails if the given hash
does not match the hash the remote host provides.

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
    curl_easy_setopt(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                     "NDVkMTQxMGQ1ODdmMjQ3MjczYjAyOTY5MmRkMjVmNDQ=");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# NOTES

Requires the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
