---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_KEYPASSWD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSH_PRIVATE_KEYFILE (3)
  - CURLOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.17.0
---

# NAME

CURLOPT_KEYPASSWD - passphrase to private key

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_KEYPASSWD, char *pwd);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used as the
password required to use the CURLOPT_SSLKEY(3) or
CURLOPT_SSH_PRIVATE_KEYFILE(3) private key. You never need a passphrase to
load a certificate but you need one to load your private key.

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
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, "key.pem");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "superman");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

This option was known as CURLOPT_SSLKEYPASSWD up to 7.16.4 and
CURLOPT_SSLCERTPASSWD up to 7.9.2.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if TLS enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
