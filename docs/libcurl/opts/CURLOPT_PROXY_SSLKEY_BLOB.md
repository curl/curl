---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLKEY_BLOB
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSLKEY (3)
  - FETCHOPT_SSLKEYTYPE (3)
  - FETCHOPT_SSLKEY_BLOB (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.71.0
---

# NAME

FETCHOPT_PROXY_SSLKEY_BLOB - private key for proxy cert from memory blob

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLKEY_BLOB,
                          struct fetch_blob *blob);
~~~

# DESCRIPTION

Pass a pointer to a fetch_blob structure that contains information (pointer and
size) about the private key for connecting to the HTTPS proxy. Compatible with
OpenSSL. The format (like "PEM") must be specified with
FETCHOPT_PROXY_SSLKEYTYPE(3).

If the blob is initialized with the flags member of struct fetch_blob set to
FETCH_BLOB_COPY, the application does not have to keep the buffer around after
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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_blob blob;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy");
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERT_BLOB, &blob);
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERTTYPE, "PEM");

    blob.data = privateKeyData;
    blob.len = privateKeySize;
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLKEY_BLOB, &blob);
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_KEYPASSWD, "s3cret");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
