---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTP_VERSION
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_ALTSVC (3)
  - FETCHOPT_HTTP09_ALLOWED (3)
  - FETCHOPT_HTTP200ALIASES (3)
  - FETCHOPT_SSLVERSION (3)
Added-in: 7.9.1
---

# NAME

FETCHOPT_HTTP_VERSION - HTTP protocol version to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTP_VERSION, long version);
~~~

# DESCRIPTION

Pass *version* a long, set to one of the values described below. They ask
libfetch to use the specific HTTP versions.

Note that the HTTP version is just a request. libfetch still prioritizes to
reuse existing connections so it might then reuse a connection using an HTTP
version you have not asked for.

## FETCH_HTTP_VERSION_NONE

We do not care about what version the library uses. libfetch uses whatever it
thinks fit.

## FETCH_HTTP_VERSION_1_0

Enforce HTTP 1.0 requests.

## FETCH_HTTP_VERSION_1_1

Enforce HTTP 1.1 requests.

## FETCH_HTTP_VERSION_2_0

Attempt HTTP 2 requests. libfetch falls back to HTTP 1.1 if HTTP 2 cannot be
negotiated with the server. (Added in 7.33.0)

When libfetch uses HTTP/2 over HTTPS, it does not itself insist on TLS 1.2 or
higher even though that is required by the specification. A user can add this
version requirement with FETCHOPT_SSLVERSION(3).

The alias *FETCH_HTTP_VERSION_2* was added in 7.43.0 to better reflect the
actual protocol name.

## FETCH_HTTP_VERSION_2TLS

Attempt HTTP 2 over TLS (HTTPS) only. libfetch falls back to HTTP 1.1 if HTTP 2
cannot be negotiated with the HTTPS server. For clear text HTTP servers,
libfetch uses 1.1. (Added in 7.47.0)

## FETCH_HTTP_VERSION_2_PRIOR_KNOWLEDGE

Issue non-TLS HTTP requests using HTTP/2 without HTTP/1.1 Upgrade. It requires
prior knowledge that the server supports HTTP/2 straight away. HTTPS requests
still do HTTP/2 the standard way with negotiated protocol version in the TLS
handshake. (Added in 7.49.0)

Since 8.10.0 if this option is set for an HTTPS request then the application
layer protocol version (ALPN) offered to the server is only HTTP/2. Prior to
that both HTTP/1.1 and HTTP/2 were offered.

## FETCH_HTTP_VERSION_3

(Added in 7.66.0) This option makes libfetch attempt to use HTTP/3 to the host
given in the URL, with fallback to earlier HTTP versions if needed.

## FETCH_HTTP_VERSION_3ONLY

(Added in 7.88.0) Setting this makes libfetch attempt to use HTTP/3 directly to
server given in the URL and does not downgrade to earlier HTTP version if the
server does not support HTTP/3.

# DEFAULT

Since fetch 7.62.0: FETCH_HTTP_VERSION_2TLS

Before that: FETCH_HTTP_VERSION_1_1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_HTTP_VERSION,
                     (long)FETCH_HTTP_VERSION_2TLS);
    ret = fetch_easy_perform(fetch);
    if(ret == FETCHE_HTTP_RETURNED_ERROR) {
      /* an HTTP response error problem */
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
