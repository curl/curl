---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_ISSUERCERT_BLOB
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ISSUERCERT_BLOB (3)
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.71.0
---

# NAME

FETCHOPT_PROXY_ISSUERCERT_BLOB - proxy issuer SSL certificate from memory blob

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_ISSUERCERT_BLOB,
                          struct fetch_blob *blob);
~~~

# DESCRIPTION

Pass a pointer to a fetch_blob struct, which contains information (pointer and
size) about a memory block with binary data of a CA certificate in PEM
format. If the option is set, an additional check against the peer certificate
is performed to verify the issuer of the HTTPS proxy is indeed the one
associated with the certificate provided by the option. This additional check
is useful in multi-level PKI where one needs to enforce that the peer
certificate is from a specific branch of the tree.

This option should be used in combination with the
FETCHOPT_PROXY_SSL_VERIFYPEER(3) option. Otherwise, the result of the
check is not considered as failure.

A specific error code (FETCHE_SSL_ISSUER_ERROR) is defined with the option,
which is returned if the setup of the SSL/TLS session has failed due to a
mismatch with the issuer of peer certificate
(FETCHOPT_PROXY_SSL_VERIFYPEER(3) has to be set too for the check to fail).

If the blob is initialized with the flags member of struct fetch_blob set to
FETCH_BLOB_COPY, the application does not have to keep the buffer around after
setting this.

This option is an alternative to FETCHOPT_PROXY_ISSUERCERT(3) which
instead expects a filename as input.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c

extern char *certificateData; /* point to the data */
size_t filesize; /* size of the data */

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_blob blob;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* using an HTTPS proxy */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://localhost:443");
    blob.data = certificateData;
    blob.len = filesize;
    blob.flags = FETCH_BLOB_COPY;
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_ISSUERCERT_BLOB, &blob);
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
