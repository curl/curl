---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_TLS_SSL_PTR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_TLS_SESSION (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - BearSSL
  - GnuTLS
  - mbedTLS
  - OpenSSL
  - Schannel
  - Secure Transport
  - wolfSSL
Added-in: 7.48.0
---

# NAME

FETCHINFO_TLS_SESSION, FETCHINFO_TLS_SSL_PTR - get TLS session info

# SYNOPSIS

```c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_TLS_SSL_PTR,
                           struct fetch_tlssessioninfo **session);

/* if you need compatibility with libfetch < 7.48.0 use
   FETCHINFO_TLS_SESSION instead: */

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_TLS_SESSION,
                           struct fetch_tlssessioninfo **session);
```

# DESCRIPTION

Pass a pointer to a *struct fetch_tlssessioninfo \*\*. The pointer is initialized
to refer to a *struct fetch_tlssessioninfo \*\* that contains an enum indicating
the SSL library used for the handshake and a pointer to the respective
internal TLS session structure of this underlying SSL library.

This option may be useful for example to extract certificate information in a
format convenient for further processing, such as manual validation. Refer to
the **LIMITATIONS** section.

```c
struct fetch_tlssessioninfo {
  fetch_sslbackend backend;
  void *internals;
};
```

The _backend_ struct member is one of the defines in the FETCHSSLBACKEND\_\*
series: FETCHSSLBACKEND_NONE (when built without TLS support),
FETCHSSLBACKEND_WOLFSSL, FETCHSSLBACKEND_SECURETRANSPORT, FETCHSSLBACKEND_GNUTLS,
FETCHSSLBACKEND_MBEDTLS, FETCHSSLBACKEND_NSS, FETCHSSLBACKEND_OPENSSL or
FETCHSSLBACKEND_SCHANNEL. (Note that the OpenSSL
forks are all reported as just OpenSSL here.)

The _internals_ struct member points to a TLS library specific pointer for
the active ("in use") SSL connection, with the following underlying types:

## GnuTLS

**gnutls_session_t**

## OpenSSL

FETCHINFO_TLS_SESSION(3): **SSL_CTX \***

FETCHINFO_TLS_SSL_PTR(3): **SSL \***
Since 7.48.0 the _internals_ member can point to these other SSL backends
as well:

## mbedTLS

**mbedTLS_ssl_context \***

## Secure Channel

**CtxtHandle \***

## Secure Transport

**SSLContext \***

## wolfSSL

**SSL \***

##

If the _internals_ pointer is NULL then either the SSL backend is not
supported, an SSL session has not yet been established or the connection is no
longer associated with the easy handle (e.g. fetch_easy_perform(3) has
returned).

# LIMITATIONS

This option has some limitations that could make it unsafe when it comes to
the manual verification of certificates.

This option only retrieves the first in-use SSL session pointer for your easy
handle, however your easy handle may have more than one in-use SSL session if
using FTP over SSL. That is because the FTP protocol has a control channel and
a data channel and one or both may be over SSL. Currently there is no way to
retrieve a second in-use SSL session associated with an easy handle.

This option has not been thoroughly tested with clear text protocols that can
be upgraded/downgraded to/from SSL: FTP, SMTP, POP3, IMAP when used with
FETCHOPT_USE_SSL(3). Though you can to retrieve the SSL pointer, it is possible
that before you can do that, data (including auth) may have already been sent
over a connection after it was upgraded.

Renegotiation. If unsafe renegotiation or renegotiation in a way that the
certificate is allowed to change is allowed by your SSL library this may occur
and the certificate may change, and data may continue to be sent or received
after renegotiation but before you are able to get the (possibly) changed SSL
pointer, with the (possibly) changed certificate information.

Instead of using this option to poll for certificate changes use
FETCHOPT_SSL_CTX_FUNCTION(3) to set a verification callback, if supported.
That is safer and does not suffer from any of the problems above.

How are you using this option? Are you affected by any of these limitations?
Please let us know by making a comment at
https://github.com/curl/curl/issues/685

# %PROTOCOLS%

# EXAMPLE

```c
#include <fetch/fetch.h>
#include <openssl/ssl.h>

FETCH *fetch;
static size_t wf(void *ptr, size_t size, size_t nmemb, void *stream)
{
  const struct fetch_tlssessioninfo *info = NULL;
  FETCHcode res = fetch_easy_getinfo(fetch, FETCHINFO_TLS_SSL_PTR, &info);
  if(info && !res) {
    if(FETCHSSLBACKEND_OPENSSL == info->backend) {
      printf("OpenSSL ver. %s\n", SSL_get_version((SSL*)info->internals));
    }
  }
  return size * nmemb;
}

int main(int argc, char **argv)
{
  FETCHcode res;
  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, wf);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
  return res;
}
```

# HISTORY

This option supersedes FETCHINFO_TLS_SESSION(3) which was added in 7.34.0.
This option is exactly the same as that option except in the case of OpenSSL.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
