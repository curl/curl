---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_ssls_export
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SHARE (3)
  - fetch_share_setopt (3)
  - fetch_easy_ssls_import (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
  - OpenSSL
  - BearSSL
  - wolfSSL
  - mbedTLS
Added-in: 8.12.0
---

# NAME

fetch_easy_ssls_export - export SSL sessions

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef FETCHcode fetch_ssls_export_function(FETCH *handle,
                                           void *userptr,
                                           const char *session_key,
                                           const unsigned char *shmac,
                                           size_t shmac_len,
                                           const unsigned char *sdata,
                                           size_t sdata_len,
                                           fetch_off_t valid_until,
                                           int ietf_tls_id,
                                           const char *alpn,
                                           size_t earlydata_max);

FETCHcode fetch_easy_ssls_export(FETCH *handle,
                               fetch_ssls_export_function *export_fn,
                               void *userptr);
~~~

# DESCRIPTION

This function iterates over all SSL session tickets that belong to the
easy handle and invokes the **export_fn** callback on each of them, as
long as the callback returns **FETCHE_OK**.

The callback may then store this information and use fetch_easy_ssls_import(3)
in another libfetch instance to add SSL session tickets again. Reuse of
SSL session tickets may result in faster handshakes and some connections
might be able to send request data in the initial packets (0-RTT).

From all the parameters passed to the **export_fn** only two need to be
persisted: either **session_key** or **shamc** and always **sdata**. All
other parameters are informative, e.g. allow the callback to act only
on specific session tickets.

Note that SSL sessions that involve a client certificate or SRP
username/password are not exported.

# Export Function Parameter

## Session Key

This is a printable, 0-terminated string that starts with **hostname:port**
the session ticket is originating from and also contains all relevant
SSL parameters used in the connection. The key also carries the name
and version number of the TLS backend used.

It is recommended to only persist **session_key** when it can be protected
from outside access. Since the hostname appears in plain text, it would
allow any third party to see how fetch has been used for.

## Salted Hash

A binary blob of **shmac_len** bytes that contains a random salt and
a cryptographic hash of the salt and **session_key**. The salt is generated
for every session individually. Storing **shmac** is recommended when
placing session tickets in a file, for example.

A third party may brute-force known hostnames, but cannot just "grep" for
them.

## Session Data

A binary blob of **sdata_len** bytes, **sdata** contains all relevant
SSL session ticket information for a later import - apart from **session_key**
and **shmac**.

## valid_until

Seconds since EPOCH (1970-01-01) until the session ticket is considered
valid.

## TLS Version

The IETF assigned number for the TLS version the session ticket originates
from. This is **0x0304** for TLSv1.3, **0x0303** for 1.2, etc. Session
tickets from version 1.3 have better security properties, so an export
might store only those.

## ALPN

The ALPN protocol that had been negotiated with the host. This may be
**NULL** if negotiation gave no result or had not been attempted.

## Early Data

The maximum amount of bytes the server supports to receive in early data
(0-RTT). This is 0 unless the server explicitly indicates support.

# %PROTOCOLS%

# EXAMPLE

~~~c
FETCHcode my_export_cb(FETCH *handle,
                      void *userptr,
                      const char *session_key,
                      const unsigned char *shmac,
                      size_t shmac_len,
                      const unsigned char *sdata,
                      size_t sdata_len,
                      fetch_off_t valid_until,
                      int ietf_tls_id,
                      const char *alpn,
                      size_t earlydata_max)
{
  /* persist sdata */
  return FETCHE_OK;
}

int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  FETCHcode rc;
  FETCH *fetch;

  sh = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_SSL_SESSION);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_SHARE, share);

    rc = fetch_easy_ssls_export(fetch, my_export_cb, NULL);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_share_cleanup(share);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
