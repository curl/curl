---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPSIG_KEY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPSIG (3)
  - CURLOPT_HTTPSIG_KEYID (3)
Protocol:
  - HTTP
Added-in: 8.21.0
---

# NAME

CURLOPT_HTTPSIG_KEY - key file for HTTP Message Signatures

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPSIG_KEY, char *path);
~~~

# DESCRIPTION

Pass a path to a file containing the private key or shared secret used for
RFC 9421 HTTP Message Signatures.

The file must contain a hex-encoded key on its first line. For **ed25519**,
this is the 32-byte private seed (64 hex characters). For **hmac-sha256**,
this is the shared secret of arbitrary length.

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/api");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG, "ed25519");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEY, "/path/to/key.hex");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEYID, "my-key-id");
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
