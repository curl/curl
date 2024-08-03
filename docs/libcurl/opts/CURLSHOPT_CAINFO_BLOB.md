---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_CAINFO_BLOB
Section: 3
Source: libcurl
See-also:
  - curl_share_setopt (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLSHOPT_CAINFO_BLOB - Shared Certificate Authority (CA) bundle in PEM format

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_CAINFO_BLOB,
                          struct curl_blob *stblob);
~~~

# DESCRIPTION

Pass a pointer to a curl_blob structure, which contains information (pointer
and size) about a memory block with binary data of PEM encoded content holding
one or more certificates to verify the HTTPS server with.

Certificates are shared across the easy handles using this shared object.

This option overrides CURLOPT_CAINFO(3).

This option is overridden by CURLOPT_CAINFO_BLOB(3).


# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h>
int test(void)
{
  char *strpem; /* strpem must point to a PEM string */
  CURLSH *share = curl_share_init();
  struct curl_blob blob;
  blob.data = strpem;
  blob.len = strlen(strpem);
  blob.flags = CURL_BLOB_COPY;
  curl_share_setopt(share, CURLSHOPT_CAINFO_BLOB, &blob);
  if(share) {
    CURL *curl = curl_easy_init();
    if(curl) {
      CURLcode res;
      curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
      res = curl_easy_perform(curl);
      curl_easy_cleanup(curl);
    }
    curl_share_cleanup(share);
  }
  return 0;
}
~~~
# HISTORY

This option is supported by the OpenSSL (since 8.10.0) backend.

# %AVAILABILITY%

# RETURN VALUE

CURLSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libcurl-errors(3) for the full list with
descriptions.
