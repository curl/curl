---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_TLS_SESSION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_TLS_SSL_PTR (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.34.0
---

# NAME

FETCHINFO_TLS_SESSION - get TLS session info

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_TLS_SESSION,
                           struct fetch_tlssessioninfo **session);
~~~

# DESCRIPTION

**This option has been superseded** by FETCHINFO_TLS_SSL_PTR(3) which
was added in 7.48.0. The only reason you would use this option instead is if
you could be using a version of libfetch earlier than 7.48.0.

This option is exactly the same as FETCHINFO_TLS_SSL_PTR(3) except in the
case of OpenSSL. If the session *backend* is FETCHSSLBACKEND_OPENSSL the
session *internals* pointer varies depending on the option:

FETCHINFO_TLS_SESSION(3) OpenSSL session *internals* is **SSL_CTX ***.

FETCHINFO_TLS_SSL_PTR(3) OpenSSL session *internals* is **SSL ***.

You can obtain an **SSL_CTX** pointer from an SSL pointer using OpenSSL
function *SSL_get_SSL_CTX(3)*. Therefore unless you need compatibility
with older versions of libfetch use FETCHINFO_TLS_SSL_PTR(3). Refer to
that document for more information.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_tlssessioninfo *tls;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res)
      printf("error: %s\n", fetch_easy_strerror(res));
    fetch_easy_getinfo(fetch, FETCHINFO_TLS_SESSION, &tls);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.48.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
