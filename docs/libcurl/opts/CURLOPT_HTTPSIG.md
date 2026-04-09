---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPSIG
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPSIG_HEADERS (3)
  - CURLOPT_HTTPSIG_KEY (3)
  - CURLOPT_HTTPSIG_KEYID (3)
  - CURLOPT_HTTPAUTH (3)
Protocol:
  - HTTP
Added-in: 8.20.0
---

# NAME

CURLOPT_HTTPSIG - RFC 9421 HTTP Message Signatures algorithm

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPSIG, char *algorithm);
~~~

# DESCRIPTION

Enable RFC 9421 HTTP Message Signatures on outgoing requests. Pass a string
specifying the signing algorithm to use.

Supported values for *algorithm*:

## ed25519

Sign with Ed25519 (RFC 8032). Requires a TLS backend with Ed25519 support
(OpenSSL 1.1.1+ or wolfSSL with `--enable-ed25519`).

## hmac-sha256

Sign with HMAC-SHA256. Works with all TLS backends.

##

Setting this option also sets CURLOPT_HTTPAUTH(3) to CURLAUTH_HTTPSIG.
The options CURLOPT_HTTPSIG_KEY(3) and CURLOPT_HTTPSIG_KEYID(3) must also
be set.

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
    curl_easy_setopt(curl, CURLOPT_HTTPSIG, "ed25519");
    curl_easy_setopt(curl, CURLOPT_HTTPSIG_KEY, "my-private-key.hex");
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
