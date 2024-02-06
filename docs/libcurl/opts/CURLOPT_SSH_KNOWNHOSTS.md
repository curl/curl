---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSH_KNOWNHOSTS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_AUTH_TYPES (3)
  - CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
---

# NAME

CURLOPT_SSH_KNOWNHOSTS - filename holding the SSH known hosts

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSH_KNOWNHOSTS, char *fname);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string holding the filename of the
known_host file to use. The known_hosts file should use the OpenSSH file
format as supported by libssh2. If this file is specified, libcurl only
accepts connections with hosts that are known and present in that file, with a
matching public key. Use CURLOPT_SSH_KEYFUNCTION(3) to alter the default
behavior on host and key matches and mismatches.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

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
    curl_easy_setopt(curl, CURLOPT_SSH_KNOWNHOSTS,
                     "/home/clarkkent/.ssh/known_hosts");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.19.6

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
