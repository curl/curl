---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_KEYPASSWD
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_PRIVATE_KEYFILE (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.17.0
---

# NAME

FETCHOPT_KEYPASSWD - passphrase to private key

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_KEYPASSWD, char *pwd);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used as the
password required to use the FETCHOPT_SSLKEY(3) or
FETCHOPT_SSH_PRIVATE_KEYFILE(3) private key. You never need a passphrase to
load a certificate but you need one to load your private key.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERT, "client.pem");
    fetch_easy_setopt(fetch, FETCHOPT_SSLKEY, "key.pem");
    fetch_easy_setopt(fetch, FETCHOPT_KEYPASSWD, "superman");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_SSLKEYPASSWD up to 7.16.4 and
FETCHOPT_SSLCERTPASSWD up to 7.9.2.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
