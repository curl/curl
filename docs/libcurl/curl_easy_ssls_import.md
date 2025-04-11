---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_ssls_import
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SHARE (3)
  - curl_share_setopt (3)
  - curl_easy_ssls_export (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
  - OpenSSL
  - BearSSL
  - wolfSSL
  - mbedTLS
Added-in: 8.12.0
---

# NAME

curl_easy_ssls_export - export SSL sessions

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_ssls_import(CURL *handle,
                               const char *session_key,
                               const unsigned char *shmac, size_t shmac_len,
                               const unsigned char *sdata, size_t sdata_len);
~~~

# DESCRIPTION

This function imports a previously exported SSL session ticket. **sdata** and
**sdata_len** must always be provided. If **session_key** is **NULL**, then
**shmac** and **shmac_len** must be given as received during the export.
See curl_easy_ssls_export(3) for a description of those.

Import of session tickets from other curl versions may fail due to changes
in the handling of **shmac** or **sdata**. A session ticket which has
already expired is silently discarded.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLSHcode sh;
  CURLSH *share = curl_share_init();
  CURLcode rc;
  CURL *curl;

  sh = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));

  curl = curl_easy_init();
  if(curl) {
    extern unsigned char *shmac, *sdata;
    size_t hlen = 4, slen = 5;

    curl_easy_setopt(curl, CURLOPT_SHARE, share);

    /* read shmac and sdata from storage */
    rc = curl_easy_ssls_import(curl, NULL, shmac, hlen, sdata, slen);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_share_cleanup(share);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3). If CURLOPT_ERRORBUFFER(3) was set with curl_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
