---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSLKEY_BLOB
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSLKEY (3)
  - CURLOPT_SSLKEYTYPE (3)
  - CURLOPT_SSLKEY_BLOB (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.71.0
---

# NAME

CURLOPT_PROXY_SSLKEY_BLOB - private key for proxy cert from memory blob

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSLKEY_BLOB,
                          struct curl_blob *blob);
~~~

# DESCRIPTION

Pass a pointer to a curl_blob structure that contains information (pointer and
size) about the private key for connecting to the HTTPS proxy. Compatible with
OpenSSL. The format (like "PEM") must be specified with
CURLOPT_PROXY_SSLKEYTYPE(3).

If the blob is initialized with the flags member of struct curl_blob set to
CURL_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c

extern char *certificateData; /* point to data */
extern size_t filesize; /* size of data */

extern char *privateKeyData; /* point to data */
extern size_t privateKeySize; /* size */

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_blob blob;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT_BLOB, &blob);
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERTTYPE, "PEM");

    blob.data = privateKeyData;
    blob.len = privateKeySize;
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY_BLOB, &blob);
    curl_easy_setopt(curl, CURLOPT_PROXY_KEYPASSWD, "s3cret");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
