---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CAINFO
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CAINFO (3)
  - FETCHOPT_CAINFO_BLOB (3)
  - FETCHOPT_CAPATH (3)
  - FETCHOPT_CA_CACHE_TIMEOUT (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.4.2
---

# NAME

FETCHOPT_CAINFO - path to Certificate Authority (CA) bundle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CAINFO, char *path);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a file holding one or
more certificates to verify the peer with.

If FETCHOPT_SSL_VERIFYPEER(3) is zero and you avoid verifying the
server's certificate, FETCHOPT_CAINFO(3) need not even indicate an
accessible file.

This option is by default set to the system path where libfetch's CA
certificate bundle is assumed to be stored, as established at build time.

(iOS and macOS) When fetch uses Secure Transport this option is supported. If
the option is not set, then fetch uses the certificates in the system and user
Keychain to verify the peer.

(Schannel) This option is supported for Schannel in Windows 7 or later but we
recommend not using it until Windows 8 since it works better starting then.
If the option is not set, then fetch uses the certificates in the Windows'
store of root certificates (the default for Schannel).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The default value for this can be figured out with FETCHINFO_CAINFO(3).

# DEFAULT

Built-in system specific. When fetch is built with Secure Transport or
Schannel, this option is not set by default.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_CAINFO, "/etc/certs/cabundle.pem");
    fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

Schannel support added in libfetch 7.60.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
