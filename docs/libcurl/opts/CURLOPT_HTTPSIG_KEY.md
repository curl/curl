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
Added-in: 8.20.0
---

# NAME

CURLOPT_HTTPSIG_KEY - hex-encoded key for HTTP Message Signatures

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPSIG_KEY, char *hexkey);
~~~

# DESCRIPTION

Pass a null-terminated string containing the hex-encoded private key or
shared secret used for RFC 9421 HTTP Message Signatures.

For **ed25519**, this is the 32-byte private seed (64 hex characters). For
**hmac-sha256**, this is the shared secret as hex; the decoded length is half
the number of hex digits, up to `CURL_MAX_INPUT_LENGTH / 2` bytes (the same
upper bound as other libcurl string options).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    curl_easy_setopt(curl, CURLOPT_HTTPSIG, (long)CURLHTTPSIG_ED25519);
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEY,
                     "9f8362f87a484a954e6e740c5b4c0e84"
                     "229139a20aa8ab56ff66586f6a7d29c5");
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
