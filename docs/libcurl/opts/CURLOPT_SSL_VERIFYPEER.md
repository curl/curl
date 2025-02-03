---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_VERIFYPEER
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CAINFO (3)
  - FETCHINFO_CAPATH (3)
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.4.2
---

# NAME

FETCHOPT_SSL_VERIFYPEER - verify the peer's SSL certificate

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_VERIFYPEER, long verify);
~~~

# DESCRIPTION

Pass a long as parameter to enable or disable.

This option determines whether fetch verifies the authenticity of the peer's
certificate. A value of 1 means fetch verifies; 0 (zero) means it does not.

When negotiating a TLS or SSL connection, the server sends a certificate
indicating its identity. fetch verifies whether the certificate is authentic,
i.e. that you can trust that the server is who the certificate says it is.
This trust is based on a chain of digital signatures, rooted in certification
authority (CA) certificates you supply. fetch uses a default bundle of CA
certificates (the path for that is determined at build time) and you can
specify alternate certificates with the FETCHOPT_CAINFO(3) option or the
FETCHOPT_CAPATH(3) option.

When FETCHOPT_SSL_VERIFYPEER(3) is enabled, and the verification fails to
prove that the certificate is signed by a CA, the connection fails.

When this option is disabled (set to zero), the CA certificates are not loaded
and the peer certificate verification is simply skipped.

Authenticating the certificate is not enough to be sure about the server. You
typically also want to ensure that the server is the server you mean to be
talking to. Use FETCHOPT_SSL_VERIFYHOST(3) for that. The check that the host
name in the certificate is valid for the hostname you are connecting to is
done independently of the FETCHOPT_SSL_VERIFYPEER(3) option.

WARNING: disabling verification of the certificate allows bad guys to
man-in-the-middle the communication without you knowing it. Disabling
verification makes the communication insecure. Just having encryption on a
transfer is not enough as you cannot be sure that you are communicating with
the correct end-point.

When libfetch uses secure protocols it trusts responses and allows for example
HSTS and Alt-Svc information to be stored and used subsequently. Disabling
certificate verification can make libfetch trust and use such information from
malicious servers.

# DEFAULT

1 - enabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Set the default value: strict certificate check please */
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
