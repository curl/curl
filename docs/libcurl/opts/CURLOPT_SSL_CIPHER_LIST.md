---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_CIPHER_LIST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSL_CIPHER_LIST (3)
  - CURLOPT_PROXY_TLS13_CIPHERS (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_TLS13_CIPHERS (3)
  - CURLOPT_USE_SSL (3)
---

# NAME

CURLOPT_SSL_CIPHER_LIST - ciphers to use for TLS

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_CIPHER_LIST, char *list);
~~~

# DESCRIPTION

Pass a char pointer, pointing to a null-terminated string holding the list of
ciphers to use for the SSL connection. The list must be syntactically correct,
it consists of one or more cipher strings separated by colons. Commas or
spaces are also acceptable separators but colons are normally used, !, - and
+ can be used as operators.

For OpenSSL and GnuTLS valid examples of cipher lists include **RC4-SHA**,
**SHA1+DES**, **TLSv1** and **DEFAULT**. The default list is normally set when
you compile OpenSSL.

For WolfSSL, valid examples of cipher lists include **ECDHE-RSA-RC4-SHA**,
**AES256-SHA:AES256-SHA256**, etc.

For BearSSL, valid examples of cipher lists include
**ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256**, or when using
IANA names
**TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256**,
etc. With BearSSL you do not add/remove ciphers. If one uses this option then
all known ciphers are disabled and only those passed in are enabled.

For Schannel, you can use this option to set algorithms but not specific
cipher suites. Refer to the ciphers lists document for algorithms.

Find more details about cipher lists on this URL:

 https://curl.se/docs/ssl-ciphers.html

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, use internal default

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "TLSv1");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.9, in 7.83.0 for BearSSL

If built TLS enabled.

# RETURN VALUE

Returns CURLE_OK if TLS is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
