---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_AUTH_TYPES
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
  - CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 (3)
  - CURLOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.16.1
---

# NAME

CURLOPT_SSH_AUTH_TYPES - auth types for SFTP and SCP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_AUTH_TYPES, long bitmask);
~~~

# DESCRIPTION

Pass a long set to a bitmask consisting of one or more of
CURLSSH_AUTH_PUBLICKEY, CURLSSH_AUTH_PASSWORD, CURLSSH_AUTH_HOST,
CURLSSH_AUTH_KEYBOARD and CURLSSH_AUTH_AGENT.

Set *CURLSSH_AUTH_ANY* to let libcurl pick a suitable one. Currently
CURLSSH_AUTH_HOST has no effect. If CURLSSH_AUTH_AGENT is used, libcurl
attempts to connect to ssh-agent or pageant and let the agent attempt the
authentication.

# DEFAULT

CURLSSH_AUTH_ANY (all available)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/file");
    curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES,
                     CURLSSH_AUTH_PUBLICKEY | CURLSSH_AUTH_KEYBOARD);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
