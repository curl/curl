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

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

This option is used to verify a new connection only. The SHA256 hash check is
performed when libcurl establishes a new SSH connection; once that connection
has been successfully verified, it is deemed vetted and may be reused without
performing the SHA256 (or any other host key) verification again, even if you
subsequently change SSH verification-related options. When this SHA256-based
verification is enabled for a new connection, libcurl does not additionally
consult CURLOPT_SSH_KNOWNHOSTS(3) or SSH host key callbacks (including
CURLOPT_SSH_HOST_PUBLIC_KEY_MD5(3)) for that connection, so you should not
expect multiple host verification methods to be applied to the same new
connection.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/file");
    curl_easy_setopt(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                     "NDVkMTQxMGQ1ODdmMjQ3MjczYjAyOTY5MmRkMjVmNDQ=");
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# NOTES

Requires the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
