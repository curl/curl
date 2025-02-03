---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_CAINFO
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_CAINFO_BLOB (3)
  - FETCHOPT_CAPATH (3)
  - FETCHOPT_PROXY_CAINFO_BLOB (3)
  - FETCHOPT_PROXY_CAPATH (3)
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_CAINFO - path to proxy Certificate Authority (CA) bundle

# SYNOPSIS

```c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_CAINFO, char *path);
```

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a char pointer to a null-terminated string naming a file holding one or
more certificates to verify the HTTPS proxy with.

If FETCHOPT_PROXY_SSL_VERIFYPEER(3) is zero and you avoid verifying the
server's certificate, FETCHOPT_PROXY_CAINFO(3) need not even indicate an
accessible file.

This option is by default set to the system path where libfetch's CA
certificate bundle is assumed to be stored, as established at build time.

(iOS and macOS only) If fetch is built against Secure Transport, then this
option is supported for backward compatibility with other SSL engines, but it
should not be set. If the option is not set, then fetch uses the certificates
in the system and user Keychain to verify the peer, which is the preferred
method of verifying the peer's certificate chain.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again and switches back to
internal default.

The default value for this can be figured out with FETCHINFO_CAINFO(3).

# DEFAULT

Built-in system specific

# %PROTOCOLS%

# EXAMPLE

```c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* using an HTTPS proxy */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://localhost:443");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_CAINFO, "/etc/certs/cabundle.pem");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
```

# NOTES

For TLS backends that do not support certificate files, the
FETCHOPT_PROXY_CAINFO(3) option is ignored. Refer to
https://fetch.se/docs/ssl-compared.html

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
