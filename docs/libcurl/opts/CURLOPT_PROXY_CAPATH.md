---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_CAPATH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_PROXY_CAINFO (3)
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_CAPATH - directory holding HTTPS proxy CA certificates

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_CAPATH, char *capath);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a directory holding
multiple CA certificates to verify the HTTPS proxy with. If libfetch is built
against OpenSSL, the certificate directory must be prepared using the OpenSSL
**c_rehash** utility. This makes sense only when
FETCHOPT_PROXY_SSL_VERIFYPEER(3) is enabled (which it is by default).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again and switch back to
internal default.

The default value for this can be figured out with FETCHINFO_CAPATH(3).

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
    /* using an HTTPS proxy */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://localhost:443");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_CAPATH, "/etc/cert-dir");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK if supported; or an error such as:

FETCHE_NOT_BUILT_IN - Not supported by the SSL backend

FETCHE_UNKNOWN_OPTION

FETCHE_OUT_OF_MEMORY
