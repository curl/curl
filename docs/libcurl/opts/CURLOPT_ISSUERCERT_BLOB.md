---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ISSUERCERT_BLOB
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CRLFILE (3)
  - CURLOPT_ISSUERCERT (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.71.0
---

# NAME

CURLOPT_ISSUERCERT_BLOB - issuer SSL certificate from memory blob

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ISSUERCERT_BLOB,
                          struct curl_blob *stblob);
~~~

# DESCRIPTION

Pass a pointer to a curl_blob structure, which contains information (pointer
and size) about a memory block with binary data of a CA certificate in PEM
format. If the option is set, an additional check against the peer certificate
is performed to verify the issuer is indeed the one associated with the
certificate provided by the option. This additional check is useful in
multi-level PKI where one needs to enforce that the peer certificate is from a
specific branch of the tree.

This option should be used in combination with the
CURLOPT_SSL_VERIFYPEER(3) option. Otherwise, the result of the check is
not considered as failure.

A specific error code (CURLE_SSL_ISSUER_ERROR) is defined with the option,
which is returned if the setup of the SSL/TLS session has failed due to a
mismatch with the issuer of peer certificate (CURLOPT_SSL_VERIFYPEER(3)
has to be set too for the check to fail).

If the blob is initialized with the flags member of struct curl_blob set to
CURL_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

This option is an alternative to CURLOPT_ISSUERCERT(3) which instead
expects a filename as input.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c

extern char *certificateData;
extern size_t filesize;

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    struct curl_blob blob;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl, CURLOPT_ISSUERCERT_BLOB, &blob);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
