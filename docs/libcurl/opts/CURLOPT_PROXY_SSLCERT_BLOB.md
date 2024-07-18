---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSLCERT_BLOB
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLCERT (3)
  - CURLOPT_PROXY_SSLCERTTYPE (3)
  - CURLOPT_PROXY_SSLKEY (3)
  - CURLOPT_SSLCERT_BLOB (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - Schannel
  - Secure Transport
Added-in: 7.71.0
---

# NAME

CURLOPT_PROXY_SSLCERT_BLOB - SSL proxy client certificate from memory blob

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSLCERT_BLOB,
                          struct curl_blob *blob);
~~~

# DESCRIPTION

Pass a pointer to a curl_blob structure, which contains information (pointer
and size) about a memory block with binary data of the certificate used to
connect to the HTTPS proxy. The format must be "P12" on Secure Transport or
Schannel. The format must be "P12" or "PEM" on OpenSSL. The string "P12" or
"PEM" must be specified with CURLOPT_PROXY_SSLCERTTYPE(3).

If the blob is initialized with the flags member of struct curl_blob set to
CURL_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

This option is an alternative to CURLOPT_PROXY_SSLCERT(3) which instead
expects a filename as input.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c

extern char *certificateData; /* point to data */
extern size_t filesize; /* size of the data */

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_blob blob;
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY, "key.pem");
    curl_easy_setopt(curl, CURLOPT_PROXY_KEYPASSWD, "s3cret");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT_BLOB, &blob);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if TLS enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
