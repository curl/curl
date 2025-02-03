---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CAINFO_BLOB
Section: 3
Source: libfetch
Protocol:
  - TLS
See-also:
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_CAPATH (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
TLS-backend:
  - BearSSL
  - OpenSSL
  - mbedTLS
  - rustls
  - wolfSSL
  - Secure Transport
  - Schannel
Added-in: 7.77.0
---

# NAME

FETCHOPT_CAINFO_BLOB - Certificate Authority (CA) bundle in PEM format

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CAINFO_BLOB,
                          struct fetch_blob *stblob);
~~~

# DESCRIPTION

Pass a pointer to a fetch_blob structure, which contains information (pointer
and size) about a memory block with binary data of PEM encoded content holding
one or more certificates to verify the HTTPS server with.

If the blob is initialized with the flags member of struct fetch_blob set to
FETCH_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

If FETCHOPT_SSL_VERIFYPEER(3) is zero and you avoid verifying the
server's certificate, FETCHOPT_CAINFO_BLOB(3) is not needed.

This option overrides FETCHOPT_CAINFO(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h>

int main(void)
{
  char *strpem; /* strpem must point to a PEM string */
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_blob blob;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    blob.data = strpem;
    blob.len = strlen(strpem);
    blob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_CAINFO_BLOB, &blob);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option is supported by the BearSSL (since 7.79.0), mbedTLS (since
7.81.0), Rustls (since 7.82.0), wolfSSL (since 8.2.0), OpenSSL, Secure
Transport and Schannel backends.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
