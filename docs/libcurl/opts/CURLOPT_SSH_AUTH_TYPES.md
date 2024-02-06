---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_AUTH_TYPES
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
  - CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 (3)
  - CURLOPT_SSH_PUBLIC_KEYFILE (3)
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

# PROTOCOLS

SFTP and SCP

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

# AVAILABILITY

CURLSSH_AUTH_HOST was added in 7.16.1, CURLSSH_AUTH_AGENT was added in 7.28.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
