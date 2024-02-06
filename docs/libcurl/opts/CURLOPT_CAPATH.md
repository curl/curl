---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CAPATH
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAPATH (3)
  - CURLOPT_CAINFO (3)
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_STDERR (3)
---

# NAME

CURLOPT_CAPATH - directory holding CA certificates

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CAPATH, char *capath);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a directory holding
multiple CA certificates to verify the peer with. If libcurl is built against
OpenSSL, the certificate directory must be prepared using the OpenSSL c_rehash
utility. This makes sense only when used in combination with the
CURLOPT_SSL_VERIFYPEER(3) option.

The CURLOPT_CAPATH(3) function apparently does not work in Windows due
to some limitation in OpenSSL.

The application does not have to keep the string around after setting this
option.

The default value for this can be figured out with CURLINFO_CAPATH(3).

# DEFAULT

A default path detected at build time.

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
    curl_easy_setopt(curl, CURLOPT_CAPATH, "/etc/cert-dir");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

This option is supported by the OpenSSL, GnuTLS and mbedTLS (since 7.56.0)
backends.

# RETURN VALUE

CURLE_OK if supported; or an error such as:

CURLE_NOT_BUILT_IN - Not supported by the SSL backend

CURLE_UNKNOWN_OPTION

CURLE_OUT_OF_MEMORY
