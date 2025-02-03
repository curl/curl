---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLCERT_BLOB
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_KEYPASSWD (3)
  - FETCHOPT_SSLCERTTYPE (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - Secure Transport
  - Schannel
  - mbedTLS
  - wolfSSL
Added-in: 7.71.0
---

# NAME

FETCHOPT_SSLCERT_BLOB - SSL client certificate from memory blob

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLCERT_BLOB,
                          struct fetch_blob *stblob);
~~~

# DESCRIPTION

Pass a pointer to a fetch_blob structure, which contains (pointer and size) a
client certificate. The format must be "P12" on Secure Transport or
Schannel. The format must be "P12" or "PEM" on OpenSSL. The format must be
"DER" or "PEM" on mbedTLS. The format must be specified with
FETCHOPT_SSLCERTTYPE(3).

If the blob is initialized with the flags member of struct fetch_blob set to
FETCH_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

This option is an alternative to FETCHOPT_SSLCERT(3) which instead
expects a filename as input.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c

extern char *certificateData; /* point to data */
extern size_t filesize; /* size of data */

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_blob stblob;
    stblob.data = certificateData;
    stblob.len = filesize;
    stblob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERT_BLOB, &stblob);
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERTTYPE, "P12");
    fetch_easy_setopt(fetch, FETCHOPT_KEYPASSWD, "s3cret");
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
