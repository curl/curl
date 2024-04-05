---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSLKEY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLCERT (3)
  - CURLOPT_PROXY_SSLKEYTYPE (3)
  - CURLOPT_SSLCERT (3)
  - CURLOPT_SSLKEY (3)
  - CURLOPT_SSLKEYTYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
---

# NAME

CURLOPT_PROXY_SSLKEY - private key file for HTTPS proxy client cert

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSLKEY, char *keyfile);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your private key used for connecting to the HTTPS proxy. The
default format is "PEM" and can be changed with
CURLOPT_PROXY_SSLKEYTYPE(3).

(Windows, iOS and Mac OS X) This option is ignored by Secure Transport and
Schannel SSL backends because they expect the private key to be already
present in the key chain or PKCS#12 file containing the certificate.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY, "key.pem");
    curl_easy_setopt(curl, CURLOPT_PROXY_KEYPASSWD, "s3cret");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.52.0

If built TLS enabled.

# RETURN VALUE

Returns CURLE_OK if TLS is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
