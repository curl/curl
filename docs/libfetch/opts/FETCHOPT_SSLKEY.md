---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLKEY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSLCERT (3)
  - FETCHOPT_SSLKEYTYPE (3)
  - FETCHOPT_SSLKEY_BLOB (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.9.3
---

# NAME

FETCHOPT_SSLKEY - private key file for TLS and SSL client cert

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLKEY, char *keyfile);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your private key. The default format is "PEM" and can be
changed with FETCHOPT_SSLKEYTYPE(3).

(Windows, iOS and macOS) This option is ignored by Secure Transport and
Schannel SSL backends because they expect the private key to be already present
in the key-chain or PKCS#12 file containing the certificate.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERT, "client.pem");
    fetch_easy_setopt(fetch, FETCHOPT_SSLKEY, "key.pem");
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
