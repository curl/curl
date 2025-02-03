---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLCERT_BLOB
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLCERT (3)
  - FETCHOPT_PROXY_SSLCERTTYPE (3)
  - FETCHOPT_PROXY_SSLKEY (3)
  - FETCHOPT_SSLCERT_BLOB (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - Schannel
  - Secure Transport
Added-in: 7.71.0
---

# NAME

FETCHOPT_PROXY_SSLCERT_BLOB - SSL proxy client certificate from memory blob

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLCERT_BLOB,
                          struct fetch_blob *blob);
~~~

# DESCRIPTION

Pass a pointer to a fetch_blob structure, which contains information (pointer
and size) about a memory block with binary data of the certificate used to
connect to the HTTPS proxy. The format must be "P12" on Secure Transport or
Schannel. The format must be "P12" or "PEM" on OpenSSL. The string "P12" or
"PEM" must be specified with FETCHOPT_PROXY_SSLCERTTYPE(3).

If the blob is initialized with the flags member of struct fetch_blob set to
FETCH_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

This option is an alternative to FETCHOPT_PROXY_SSLCERT(3) which instead
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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_blob blob;
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLKEY, "key.pem");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_KEYPASSWD, "s3cret");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERT_BLOB, &blob);
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
