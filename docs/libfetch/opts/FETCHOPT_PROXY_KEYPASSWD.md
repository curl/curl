---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_KEYPASSWD
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_KEYPASSWD (3)
  - FETCHOPT_PROXY_SSLKEY (3)
  - FETCHOPT_SSH_PRIVATE_KEYFILE (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_KEYPASSWD - passphrase for the proxy private key

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_KEYPASSWD, char *pwd);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a pointer to a null-terminated string as parameter. It is used as the
password required to use the FETCHOPT_PROXY_SSLKEY(3) private key. You never
need a passphrase to load a certificate but you need one to load your private
key.

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
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy:443");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_KEYPASSWD, "superman");
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
