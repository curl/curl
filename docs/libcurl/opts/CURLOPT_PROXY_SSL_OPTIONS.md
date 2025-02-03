---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSL_OPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLVERSION (3)
  - FETCHOPT_PROXY_SSL_CIPHER_LIST (3)
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_SSL_CIPHER_LIST (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSL_OPTIONS - HTTPS proxy SSL behavior options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSL_OPTIONS,
                          long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask to tell libfetch about specific SSL
behaviors. Available bits:

## FETCHSSLOPT_ALLOW_BEAST

Tells libfetch to not attempt to use any workarounds for a security flaw in the
SSL3 and TLS1.0 protocols. If this option is not used or this bit is set to 0,
the SSL layer libfetch uses may use a work-around for this flaw although it
might cause interoperability problems with some (older) SSL implementations.
WARNING: avoiding this work-around lessens the security, and by setting this
option to 1 you ask for exactly that. This option is only supported for Secure
Transport and OpenSSL.

## FETCHSSLOPT_NO_REVOKE

Tells libfetch to disable certificate revocation checks for those SSL backends
where such behavior is present. This option is only supported for Schannel
(the native Windows SSL library), with an exception in the case of Windows'
Untrusted Publishers block list which it seems cannot be bypassed. (Added in
7.44.0)

## FETCHSSLOPT_NO_PARTIALCHAIN

Tells libfetch to not accept "partial" certificate chains, which it otherwise
does by default. This option is only supported for OpenSSL and fails the
certificate verification if the chain ends with an intermediate certificate
and not with a root cert. (Added in 7.68.0)

## FETCHSSLOPT_REVOKE_BEST_EFFORT

Tells libfetch to ignore certificate revocation checks in case of missing or
offline distribution points for those SSL backends where such behavior is
present. This option is only supported for Schannel (the native Windows SSL
library). If combined with *FETCHSSLOPT_NO_REVOKE*, the latter takes
precedence. (Added in 7.70.0)

## FETCHSSLOPT_NATIVE_CA

Tell libfetch to use the operating system's native CA store for certificate
verification. If you set this option and also set a CA certificate file or
directory then during verification those certificates are searched in addition
to the native CA store.

Works with wolfSSL on Windows, Linux (Debian, Ubuntu, Gentoo, Fedora, RHEL),
macOS, Android and iOS (added in 8.3.0), with GnuTLS (added in 8.5.0) or on
Windows when built to use OpenSSL (Added in 7.71.0).

## FETCHSSLOPT_AUTO_CLIENT_CERT

Tell libfetch to automatically locate and use a client certificate for
authentication, when requested by the server. This option is only supported
for Schannel (the native Windows SSL library). Prior to 7.77.0 this was the
default behavior in libfetch with Schannel. Since the server can request any
certificate that supports client authentication in the OS certificate store it
could be a privacy violation and unexpected.
(Added in 7.77.0)

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy");
    /* weaken TLS only for use with silly proxies */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSL_OPTIONS, FETCHSSLOPT_ALLOW_BEAST |
                     FETCHSSLOPT_NO_REVOKE);
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
