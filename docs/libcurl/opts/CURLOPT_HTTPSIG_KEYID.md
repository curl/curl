---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPSIG_KEYID
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPSIG (3)
  - CURLOPT_HTTPSIG_KEY (3)
Protocol:
  - HTTP
Added-in: 8.20.0
---

# NAME

CURLOPT_HTTPSIG_KEYID - key identifier for HTTP Message Signatures

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPSIG_KEYID, char *keyid);
~~~

# DESCRIPTION

Pass a null-terminated string that identifies the key used for RFC 9421 HTTP
Message Signatures. This value is included as the `keyid` parameter in the
`Signature-Input` header, allowing the server to look up the corresponding
verification key.

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
