---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ISSUERCERT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CRLFILE (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.19.0
---

# NAME

FETCHOPT_ISSUERCERT - issuer SSL certificate filename

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ISSUERCERT, char *file);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a *file* holding a CA
certificate in PEM format. If the option is set, an additional check against
the peer certificate is performed to verify the issuer is indeed the one
associated with the certificate provided by the option. This additional check
is useful in multi-level PKI where one needs to enforce that the peer
certificate is from a specific branch of the tree.

This option makes sense only when used in combination with the
FETCHOPT_SSL_VERIFYPEER(3) option. Otherwise, the result of the check is
not considered as failure.

A specific error code (FETCHE_SSL_ISSUER_ERROR) is defined with the option,
which is returned if the setup of the SSL/TLS session has failed due to a
mismatch with the issuer of peer certificate (FETCHOPT_SSL_VERIFYPEER(3)
has to be set too for the check to fail). (Added in 7.19.0)

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_ISSUERCERT, "/etc/certs/cacert.pem");
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
