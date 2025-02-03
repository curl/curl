---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_global_sslset
Section: 3
Source: libfetch
See-also:
  - fetch_global_init (3)
  - libfetch (3)
Protocol:
  - All
Added-in: 7.56.0
---

# NAME

fetch_global_sslset - select SSL backend to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHsslset fetch_global_sslset(fetch_sslbackend id,
                              const char *name,
                              const fetch_ssl_backend ***avail);
~~~

# DESCRIPTION

This function configures at runtime which SSL backend to use with
libfetch. This function can only be used to select an SSL backend once, and it
must be called **before** fetch_global_init(3).

The backend can be identified by the *id*
(e.g. **FETCHSSLBACKEND_OPENSSL**). The backend can also be specified via the
*name* parameter for a case insensitive match (passing
**FETCHSSLBACKEND_NONE** as *id*). If both *id* and *name* are
specified, the *name* is ignored.

If neither *id* nor *name* are specified, the function fails with
**FETCHSSLSET_UNKNOWN_BACKEND** and set the *avail* pointer to the
NULL-terminated list of available backends. The available backends are those
that this particular build of libfetch supports.

Since libfetch 7.60.0, the *avail* pointer is always set to the list of
alternatives if non-NULL.

Upon success, the function returns **FETCHSSLSET_OK**.

If the specified SSL backend is not available, the function returns
**FETCHSSLSET_UNKNOWN_BACKEND** and sets the *avail* pointer to a
NULL-terminated list of available SSL backends. In this case, you may call the
function again to try to select a different backend.

The SSL backend can be set only once. If it has already been set, a subsequent
attempt to change it results in a **FETCHSSLSET_TOO_LATE** getting returned.

This function is thread-safe since libfetch 7.84.0 if
fetch_version_info(3) has the FETCH_VERSION_THREADSAFE feature bit set
(most platforms).

If this is not thread-safe, you must not call this function when any other
thread in the program (i.e. a thread sharing the same memory) is running.
This does not just mean no other thread that is using libfetch.

# OpenSSL

The name "OpenSSL" is used for all versions of OpenSSL and its associated
forks/flavors in this function. OpenSSL, BoringSSL, LibreSSL, quictls and
AmiSSL are all supported by libfetch, but in the eyes of
fetch_global_sslset(3) they are all just "OpenSSL". They all mostly
provide the same API.

fetch_version_info(3) can return more specific info about the exact
OpenSSL flavor and version number is use.

# struct

~~~c
typedef struct {
  fetch_sslbackend id;
  const char *name;
} fetch_ssl_backend;

typedef enum {
  FETCHSSLBACKEND_NONE = 0,
  FETCHSSLBACKEND_OPENSSL = 1, /* or one of its forks */
  FETCHSSLBACKEND_GNUTLS = 2,
  FETCHSSLBACKEND_NSS = 3,
  FETCHSSLBACKEND_GSKIT = 5, /* deprecated */
  FETCHSSLBACKEND_POLARSSL = 6, /* deprecated */
  FETCHSSLBACKEND_WOLFSSL = 7,
  FETCHSSLBACKEND_SCHANNEL = 8,
  FETCHSSLBACKEND_SECURETRANSPORT = 9,
  FETCHSSLBACKEND_AXTLS = 10, /* deprecated */
  FETCHSSLBACKEND_MBEDTLS = 11,
  FETCHSSLBACKEND_MESALINK = 12, /* deprecated */
  FETCHSSLBACKEND_BEARSSL = 13,
  FETCHSSLBACKEND_RUSTLS = 14
} fetch_sslbackend;
~~~

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  int i;
  /* choose a specific backend */
  fetch_global_sslset(FETCHSSLBACKEND_WOLFSSL, NULL, NULL);

  /* list the available ones */
  const fetch_ssl_backend **list;
  fetch_global_sslset(FETCHSSLBACKEND_NONE, NULL, &list);

  for(i = 0; list[i]; i++)
    printf("SSL backend #%d: '%s' (ID: %d)\n",
           i, list[i]->name, list[i]->id);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

If this function returns *FETCHSSLSET_OK*, the backend was successfully
selected.

If the chosen backend is unknown (or support for the chosen backend has not
been compiled into libfetch), the function returns
*FETCHSSLSET_UNKNOWN_BACKEND*.

If the backend had been configured previously, or if fetch_global_init(3)
has already been called, the function returns *FETCHSSLSET_TOO_LATE*.

If this libfetch was built completely without SSL support, with no backends at
all, this function returns *FETCHSSLSET_NO_BACKENDS*.
