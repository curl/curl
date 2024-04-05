---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSLCERT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLCERTTYPE (3)
  - CURLOPT_PROXY_SSLKEY (3)
  - CURLOPT_SSLCERT (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - Schannel
  - Secure Transport
  - wolfSSL
---

# NAME

CURLOPT_PROXY_SSLCERT - HTTPS proxy client certificate

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSLCERT, char *cert);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your client certificate used to connect to the HTTPS proxy.
The default format is "P12" on Secure Transport and "PEM" on other engines,
and can be changed with CURLOPT_PROXY_SSLCERTTYPE(3).

With Secure Transport, this can also be the nickname of the certificate you
wish to authenticate with as it is named in the security database. If you want
to use a file from the current directory, please precede it with "./" prefix,
in order to avoid confusion with a nickname.

When using a client certificate, you most likely also need to provide a
private key with CURLOPT_PROXY_SSLKEY(3).

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

# RETURN VALUE

Returns CURLE_OK if TLS enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
